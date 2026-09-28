using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Wodsoft.StunServer
{
    public abstract class StunServiceBase
    {
        private readonly ArrayPool<byte> _pool;

        protected StunServiceBase()
        {
            _pool = ArrayPool<byte>.Create();
        }

        protected byte[] RentBuffer()
        {
            return _pool.Rent(1240);
        }

        protected void ReturnBuffer(byte[] buffer)
        {
            _pool.Return(buffer);
        }

        protected byte[]? HandleRequest(Span<byte> request, Span<byte> remoteAddress, ref ushort remotePort, Span<byte> thisAddress, ushort thisPort,
            Span<byte> otherAddress, ushort otherPort, out bool changeAddress, out bool changePort, out int responseLength)
        {
            changeAddress = false;
            changePort = false;
            responseLength = 0;
            ref MessageHeader header = ref MemoryMarshal.AsRef<MessageHeader>(request);
            if (header.MessageType != MessageType.Request)
                return null;
            bool isRFC5389 = header.MagicCookie == 0x42A41221;
            var length = request.Length;
            if (header.MessageLength + 20 != length)
                return null;
            var current = 20;
            var transactionId = request.Slice(8, 12);
            var state = new StunServiceState();
            List<ushort> unknownAttributes = new List<ushort>();
            //Span<byte> replyEndAddress = default;
            //ushort replyPort = 0;
            //bool hasMessageIntegrity = false;
            bool messageIntegrityFailed = false;
            while (current < length)
            {
                if (length - current < 4)
                    return null;
                ref MessageAttributeType attributeType = ref MemoryMarshal.AsRef<MessageAttributeType>(request.Slice(current, 2));
                //rfc3489 11.2
                Span<byte> data;
                var attributeLength = BinaryPrimitives.ReadUInt16BigEndian(request.Slice(current + 2));
                if (length - current - 4 < attributeLength)
                    return null;
                data = request.Slice(current + 4, attributeLength);
                current += 4 + attributeLength;
                if (!IsValidAttribute(attributeType))
                {
                    if (BinaryPrimitives.ReverseEndianness((ushort)attributeType) <= 0x7FFFu)
                        unknownAttributes.Add((ushort)attributeType);
                    continue;
                }
                if (!HandleAttribute(ref state, data, attributeType, current == length))
                    return null;
            }
            if (state.HasMessageIntegrity && !request.ValidateMessageIntegrity())
                messageIntegrityFailed = true;
            responseLength = 20;
            bool hasError = false;
            var response = RentBuffer();
            var buffer = response.AsSpan(20);
            if (messageIntegrityFailed)
            {
                hasError = true;
                CreateErrorResponseAttribute(ref buffer, 431, "The Binding Request contained a MESSAGE-INTEGRITY attribute, but the HMAC failed verification. This could be a sign of a potential attack, or client implementation error.", ref responseLength);
            }
            //else
            //{
            //    if (!hasMessageIntegrity)
            //    {
            //        hasError = true;
            //        responseAttributes.Add(CreateErrorResponseAttribute(401, "The Binding Request did not contain a MESSAGE-INTEGRITY attribute.", ref responseLength));
            //    }
            //}
            if (unknownAttributes.Count != 0)
            {
                hasError = true;
                CreateErrorResponseAttribute(ref buffer, 420, "The server did not understand a mandatory attribute in the request.", ref responseLength);
                CreateUnknownAttributesAttribute(ref buffer, unknownAttributes, ref responseLength);
            }
            if (!hasError)
            {
                CreateMappedAddressAttribute(ref buffer, remoteAddress, remotePort, ref responseLength);
                if (!state.ReplyAddress.IsEmpty)
                    CreateReflectedFromAttribute(ref buffer, state.ReplyAddress, state.ReplyPort, ref responseLength);
                if (isRFC5389)
                {
                    CreateXORMappedAddressAttribute(ref buffer, transactionId, remoteAddress, remotePort, ref responseLength);
                    CreateResponseOriginAttribute(ref buffer, thisAddress, thisPort, ref responseLength);
                    CreateOtherAddressAttribute(ref buffer, otherAddress, otherPort, ref responseLength);
                }
                else
                {
                    CreateSourceAddressAttribute(ref buffer, thisAddress, thisPort, ref responseLength);
                    CreateChangedAddressAttribute(ref buffer, otherAddress, otherPort, ref responseLength);
                }
                //if (replyEndPoint != null)
                //    responseAttributes.Add(CreateReflectedFromAttribute(endPoint.Address, endPoint.Port, ref responseLength));
            }
            if (!hasError && state.HasMessageIntegrity)
                responseLength += 28;
            header = ref MemoryMarshal.AsRef<MessageHeader>(response.AsSpan());
            header.MessageType = hasError ? MessageType.Error : MessageType.Response;
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2), (ushort)(responseLength - 20));
            if (isRFC5389)
                header.MagicCookie = 0x42A41221u;
            transactionId.CopyTo(response.AsSpan(8, 12));
            var responseData = response.AsSpan(20);
            if (!hasError && state.HasMessageIntegrity)
                response.AsSpan().SetMessageIntegrity();
            if (!state.ReplyAddress.IsEmpty)
                remoteAddress = state.ReplyAddress;
            if (state.ReplyPort != default)
                remotePort = state.ReplyPort;
            changeAddress = state.ChangeAddress;
            changePort = state.ChangePort;
            return response;
        }

        protected virtual bool IsValidAttribute(MessageAttributeType attributeType)
        {
            if (!attributeType.IsValid())
                return false;
            switch (attributeType)
            {
                case MessageAttributeType.MappedAddress:
                case MessageAttributeType.SourceAddress:
                case MessageAttributeType.ChangedAddress:
                case MessageAttributeType.UserName:
                case MessageAttributeType.Password:
                case MessageAttributeType.ErrorCode:
                case MessageAttributeType.Unknown:
                case MessageAttributeType.ReflectedFrom:
                case MessageAttributeType.Padding:
                case MessageAttributeType.Realm:
                case MessageAttributeType.Nonce:
                    return false;
                default:
                    return true;
            }
        }

        protected virtual bool HandleAttribute(ref StunServiceState state, Span<byte> data, MessageAttributeType attributeType, bool isEnd)
        {
            switch (attributeType)
            {
                case MessageAttributeType.ResponseAddress:
                    if (data.Length < 4)
                        return false;
                    switch (data[1])
                    {
                        case 1:
                            if (data.Length < 8)
                                return false;
                            state.ReplyAddress = data.Slice(4, 4);
                            state.ReplyPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(2, 2)); ;
                            break;
                        case 2:
                            if (data.Length < 20)
                                return false;
                            state.ReplyAddress = data.Slice(4, 16);
                            state.ReplyPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(2, 2));
                            break;
                        default:
                            return false;
                    }
                    return true;
                case MessageAttributeType.ChangeRequest:
                    if (data.Length != 4)
                        return false;
                    if ((data[3] & (byte)2) == (byte)2)
                        state.ChangePort = true;
                    if ((data[3] & (byte)4) == (byte)4)
                        state.ChangeAddress = true;
                    return true;
                case MessageAttributeType.ResponsePort:
                    if (data.Length != 4)
                        return false;
                    state.ReplyPort = BinaryPrimitives.ReadUInt16BigEndian(data);
                    return true;
                case MessageAttributeType.MessageIntegrity:
                    if (!isEnd)
                        return false;
                    state.HasMessageIntegrity = true;
                    return true;
                default:
                    return false;
            }
        }

        //rfc3489 11.2.9
        private void CreateErrorResponseAttribute(ref Span<byte> buffer, ushort code, string message, ref int length)
        {
            var messageLength = Encoding.UTF8.GetByteCount(message);
            if (messageLength > ushort.MaxValue - 4)
                throw new InvalidOperationException("Message data must less than or equal to 65531.");
            var attributeLength = 8 + Encoding.UTF8.GetByteCount(message);
            length += attributeLength;
            MemoryMarshal.Write(buffer, MessageAttributeType.ErrorCode);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), (ushort)(messageLength + 4));
            //error code
            buffer[6] = (byte)(code / 100);
            buffer[7] = (byte)(code % 100);
            Encoding.UTF8.GetBytes(message, buffer.Slice(8, messageLength));
            buffer = buffer.Slice(attributeLength);
        }

        //rfc3489 11.2.10
        private void CreateUnknownAttributesAttribute(ref Span<byte> buffer, List<ushort> unknownAttributes, ref int length)
        {
            var attributeLength = unknownAttributes.Count / 4 * 12;
            length += attributeLength;
            for (int i = 0; i < unknownAttributes.Count; i += 4)
            {
                MemoryMarshal.Write(buffer, MessageAttributeType.Unknown);
                BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), 8);
                BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(4), unknownAttributes[i]);
                for (int j = 1; j < 3; j++)
                {
                    if (i + j < unknownAttributes.Count)
                        BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice((i + j) * 4), unknownAttributes[i + j]);
                    else
                        BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice((i + j) * 4), unknownAttributes[i]);
                }
            }
            buffer = buffer.Slice(attributeLength);
        }

        private void CreateMappedAddressAttribute(ref Span<byte> buffer, Span<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.MappedAddress, address, port, ref length);
        }

        private void CreateSourceAddressAttribute(ref Span<byte> buffer, Span<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.SourceAddress, address, port, ref length);
        }

        private void CreateChangedAddressAttribute(ref Span<byte> buffer, Span<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.ChangedAddress, address, port, ref length);
        }

        private void CreateReflectedFromAttribute(ref Span<byte> buffer, Span<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.ReflectedFrom, address, port, ref length);
        }

        private void CreateOtherAddressAttribute(ref Span<byte> buffer, Span<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.OtherAddress, address, port, ref length);
        }

        private void CreateResponseOriginAttribute(ref Span<byte> buffer, Span<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.ResponseOrigin, address, port, ref length);
        }

        private void CreateXORMappedAddressAttribute(ref Span<byte> buffer, Span<byte> transactionId, Span<byte> address, ushort port, ref int length)
        {
            int attributeLength;
            if (address.Length == 4)
                attributeLength = 12;
            else
                attributeLength = 24;
            length += attributeLength;
            MemoryMarshal.Write(buffer, MessageAttributeType.XORMappedAddress);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), (ushort)(attributeLength - 4));
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(6), (ushort)(port ^ 0x2112u));
            if (address.Length == 4)
                buffer[5] = 1;
            else
                buffer[5] = 2;
            address.CopyTo(buffer.Slice(8));
            //0x42A41221
            buffer[8] ^= 0x21;
            buffer[9] ^= 0x12;
            buffer[10] ^= 0xA4;
            buffer[11] ^= 0x42;
            if (address.Length != 4)
            {
                for (int i = 0; i < 12; i++)
                {
                    buffer[12 + i] ^= transactionId[i];
                }
            }
            buffer = buffer.Slice(attributeLength);
        }

        private void CreateAddressAttribute(ref Span<byte> buffer, MessageAttributeType attributeType, Span<byte> address, ushort port, ref int length)
        {
            int attributeLength;
            if (address.Length == 4)
                attributeLength = 12;
            else
                attributeLength = 24;
            length += attributeLength;
            MemoryMarshal.Write(buffer, attributeType);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), (ushort)(attributeLength - 4));
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(6), (ushort)port);
            if (address.Length == 4)
                buffer[5] = 1;
            else
                buffer[5] = 2;
            address.CopyTo(buffer.Slice(8));
            buffer = buffer.Slice(attributeLength);
        }
    }
}
