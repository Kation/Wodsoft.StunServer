using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Wodsoft.StunServer
{
    public abstract class StunServiceBase
    {
        private const int NonceLifetimeSeconds = 600;
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

        protected async ValueTask<StunRequestResult> HandleRequestAsync(ReadOnlyMemory<byte> request, ReadOnlyMemory<byte> remoteAddress, ushort remotePort, ReadOnlyMemory<byte> thisAddress, ushort thisPort,
            ReadOnlyMemory<byte> otherAddress, ushort otherPort)
        {
            ref readonly MessageHeader header = ref MemoryMarshal.AsRef<MessageHeader>(request.Span);
            if (header.MessageType != MessageType.Request)
                return default;
            bool isRFC5389 = header.MagicCookie == 0x42A41221;
            var length = request.Length;
            if (header.MessageLength + 20 != length)
                return default;
            var current = 20;
            var transactionId = request.Slice(8, 12);
            var state = new StunServiceState
            {
                MessageIntegrityOffset = -1
            };
            List<ushort> unknownAttributes = new List<ushort>();
            var lastRequiredOffset = -1;
            while (current < length)
            {
                if (length - current < 4)
                    return default;
                var attributeOffset = current;
                ref readonly MessageAttributeType attributeType = ref MemoryMarshal.AsRef<MessageAttributeType>(request.Slice(current, 2).Span);
                var attributeLength = BinaryPrimitives.ReadUInt16BigEndian(request.Slice(current + 2).Span);
                var paddedLength = (attributeLength + 3) & ~3;
                if (length - current - 4 < paddedLength)
                    return default;
                var data = request.Slice(current + 4, attributeLength);
                current += 4 + paddedLength;
                var wireType = BinaryPrimitives.ReverseEndianness((ushort)attributeType);
                if (wireType <= 0x7FFFu)
                    lastRequiredOffset = attributeOffset;
                if (!IsValidAttribute(attributeType))
                {
                    if (wireType <= 0x7FFFu)
                        unknownAttributes.Add((ushort)attributeType);
                    continue;
                }
                if (!HandleAttribute(ref state, data, attributeType, current == length, attributeOffset))
                    return default;
            }

            var useSha256 = state.MessageIntegrity.Length == 32;
            var hasIntegrity = !state.MessageIntegrity.IsEmpty;
            var integrityOutOfOrder = hasIntegrity && lastRequiredOffset > state.MessageIntegrityOffset;
            ushort errorCode = 0;
            string? errorReason = null;
            var challenge = false;
            var authorized = false;
            if (integrityOutOfOrder || !IsPasswordAlgorithmPaired(state))
            {
                errorCode = 400;
                errorReason = "Bad Request";
            }
            else if (unknownAttributes.Count != 0)
            {
                errorCode = 420;
                errorReason = "The server did not understand a mandatory attribute in the request.";
            }
            else if (RequireAuthorized)
            {
                var longTerm = !AuthorizationRealm.IsEmpty;
                if (longTerm)
                {
                    if (!hasIntegrity || state.UserName.IsEmpty || !HasMatchingRealm(state) || state.Nonce.IsEmpty)
                    {
                        errorCode = 401;
                        errorReason = "Unauthorized";
                        challenge = true;
                    }
                    else if (!IsNonceCurrent(state.Nonce.Span))
                    {
                        errorCode = 438;
                        errorReason = "Stale Nonce";
                        challenge = true;
                    }
                    else if (!await VerifyRequestIntegrityAsync(request, state, longTerm: true).ConfigureAwait(false))
                    {
                        errorCode = 401;
                        errorReason = "Unauthorized";
                        challenge = true;
                    }
                    else
                        authorized = true;
                }
                else if (!hasIntegrity || state.UserName.IsEmpty || !await VerifyRequestIntegrityAsync(request, state, longTerm: false).ConfigureAwait(false))
                {
                    errorCode = 401;
                    errorReason = "Unauthorized";
                }
                else
                    authorized = true;
            }

            ReadOnlyMemory<byte> password = default;
            if (authorized)
            {
                password = await GetPasswordAsync(state.UserName).ConfigureAwait(false);
                if (password.IsEmpty)
                {
                    authorized = false;
                    errorCode = 401;
                    errorReason = "Unauthorized";
                    challenge = !AuthorizationRealm.IsEmpty;
                }
            }

            int responseLength = 20;
            var hasError = errorCode != 0;
            var response = RentBuffer();
            var buffer = response.AsSpan(20);
            if (hasError)
            {
                CreateErrorResponseAttribute(ref buffer, errorCode, errorReason!, ref responseLength);
                if (errorCode == 420)
                    CreateUnknownAttributesAttribute(ref buffer, unknownAttributes, ref responseLength);
                if (challenge)
                    WriteChallenge(ref buffer, ref responseLength);
            }
            else
            {
                CreateMappedAddressAttribute(ref buffer, remoteAddress, remotePort, ref responseLength);
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
                    if (!state.ReplyAddress.IsEmpty || state.ReplyPort != 0)
                        CreateReflectedFromAttribute(ref buffer, remoteAddress, remotePort, ref responseLength);
                }
            }
            ref var responseHeader = ref MemoryMarshal.AsRef<MessageHeader>(response.AsSpan());
            responseHeader.MessageType = hasError ? MessageType.Error : MessageType.Response;
            BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2), (ushort)(responseLength - 20));
            if (isRFC5389)
                responseHeader.MagicCookie = 0x42A41221u;
            transactionId.Span.CopyTo(response.AsSpan(8, 12));
            if (authorized)
            {
                SignResponse(response, responseLength, password.Span, !AuthorizationRealm.IsEmpty, useSha256, state.UserName.Span, state.Realm.Span);
                responseLength += useSha256 ? 36 : 24;
            }
            return new StunRequestResult
            {
                Response = response,
                ResponseLength = responseLength,
                ResponsePort = state.ReplyPort,
                ResponseAddress = state.ReplyAddress,
                ChangeAddress = state.ChangeAddress,
                ChangePort = state.ChangePort
            };
        }

        protected virtual bool RequireAuthorized => false;

        protected virtual ReadOnlyMemory<byte> AuthorizationRealm => default;

        protected virtual async ValueTask<bool> ValidateAuthorizationAsync(ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> hash)
        {
            var password = await GetPasswordAsync(username).ConfigureAwait(false);
            if (password.IsEmpty)
                return false;
            return MessageExtensions.VerifyMessageIntegrity(message.Span, password.Span, hash.Span);
        }

        protected virtual async ValueTask<bool> ValidateAuthorizationAsync(ReadOnlyMemory<byte> username, ReadOnlyMemory<byte> realm, ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> hash)
        {
            _ = nonce;
            var password = await GetPasswordAsync(username).ConfigureAwait(false);
            if (password.IsEmpty)
                return false;
            return VerifyLongTermIntegrity(username.Span, realm.Span, password.Span, message.Span, hash.Span);
        }

        protected virtual ValueTask<ReadOnlyMemory<byte>> GetPasswordAsync(ReadOnlyMemory<byte> username) => throw new NotSupportedException();

        protected virtual bool IsValidAttribute(MessageAttributeType attributeType)
        {
            if (!attributeType.IsValid())
                return false;
            switch (attributeType)
            {
                case MessageAttributeType.MappedAddress:
                case MessageAttributeType.SourceAddress:
                case MessageAttributeType.ChangedAddress:
                case MessageAttributeType.Password:
                case MessageAttributeType.ErrorCode:
                case MessageAttributeType.Unknown:
                case MessageAttributeType.ReflectedFrom:
                case MessageAttributeType.Padding:
                    return false;
                default:
                    return true;
            }
        }

        protected virtual bool HandleAttribute(ref StunServiceState state, ReadOnlyMemory<byte> data, MessageAttributeType attributeType, bool isEnd, int offset)
        {
            switch (attributeType)
            {
                case MessageAttributeType.ResponseAddress:
                    if (data.Length < 4)
                        return false;
                    switch (data.Span[1])
                    {
                        case 1:
                            if (data.Length < 8)
                                return false;
                            state.ReplyAddress = data.Slice(4, 4);
                            state.ReplyPort = BinaryPrimitives.ReadUInt16BigEndian(data.Span.Slice(2, 2));
                            break;
                        case 2:
                            if (data.Length < 20)
                                return false;
                            state.ReplyAddress = data.Slice(4, 16);
                            state.ReplyPort = BinaryPrimitives.ReadUInt16BigEndian(data.Span.Slice(2, 2));
                            break;
                        default:
                            return false;
                    }
                    return true;
                case MessageAttributeType.ChangeRequest:
                    if (data.Length != 4)
                        return false;
                    if ((data.Span[3] & (byte)2) == (byte)2)
                        state.ChangePort = true;
                    if ((data.Span[3] & (byte)4) == (byte)4)
                        state.ChangeAddress = true;
                    return true;
                case MessageAttributeType.ResponsePort:
                    if (data.Length != 4)
                        return false;
                    state.ReplyPort = BinaryPrimitives.ReadUInt16BigEndian(data.Span);
                    return true;
                case MessageAttributeType.UserName:
                    if (!state.UserName.IsEmpty)
                        return false;
                    state.UserName = data;
                    return true;
                case MessageAttributeType.Realm:
                    if (!state.Realm.IsEmpty)
                        return false;
                    state.Realm = data;
                    return true;
                case MessageAttributeType.Nonce:
                    if (!state.Nonce.IsEmpty)
                        return false;
                    state.Nonce = data;
                    return true;
                case MessageAttributeType.PasswordAlgorithm:
                    if (data.Length < 4 || state.PasswordAlgorithm != 0)
                        return false;
                    var algorithm = BinaryPrimitives.ReadUInt16BigEndian(data.Span);
                    var parameterLength = BinaryPrimitives.ReadUInt16BigEndian(data.Span.Slice(2));
                    if (parameterLength != 0 || data.Length != 4 || (algorithm != MessageExtensions.PasswordAlgorithmMd5 && algorithm != MessageExtensions.PasswordAlgorithmSha256))
                        return false;
                    state.PasswordAlgorithm = algorithm;
                    return true;
                case MessageAttributeType.PasswordAlgorithms:
                    return true;
                case MessageAttributeType.MessageIntegrity:
                    if (data.Length != 20 || state.MessageIntegrity.Length == 20)
                        return false;
                    if (state.MessageIntegrity.Length != 32)
                    {
                        state.MessageIntegrityOffset = offset;
                        state.MessageIntegrity = data;
                    }
                    return true;
                case MessageAttributeType.MessageIntegritySHA256:
                    if (data.Length != 32 || state.MessageIntegrity.Length == 32)
                        return false;
                    state.MessageIntegrityOffset = offset;
                    state.MessageIntegrity = data;
                    return true;
                default:
                    return false;
            }
        }

        private async ValueTask<bool> VerifyRequestIntegrityAsync(ReadOnlyMemory<byte> request, StunServiceState state, bool longTerm)
        {
            var integrityOffset = state.MessageIntegrityOffset;
            if (integrityOffset < 20)
                return false;
            var hash = state.MessageIntegrity;
            var attributeSize = hash.Length == 32 ? 36 : 24;
            var input = RentBuffer();
            try
            {
                if (integrityOffset > input.Length)
                    return false;
                request.Span.Slice(0, integrityOffset).CopyTo(input);
                BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(2), (ushort)(integrityOffset - 20 + attributeSize));
                var message = input.AsMemory(0, integrityOffset);
                if (longTerm)
                    return await ValidateAuthorizationAsync(state.UserName, state.Realm, state.Nonce, message, hash).ConfigureAwait(false);
                return await ValidateAuthorizationAsync(state.UserName, message, hash).ConfigureAwait(false);
            }
            finally
            {
                ReturnBuffer(input);
            }
        }

        private static bool VerifyLongTermIntegrity(ReadOnlySpan<byte> username, ReadOnlySpan<byte> realm, ReadOnlySpan<byte> password, ReadOnlySpan<byte> message, ReadOnlySpan<byte> hash)
        {
            var sha256 = hash.Length == 32;
            var keyLength = sha256 ? 32 : 16;
            Span<byte> key = stackalloc byte[32];
            MessageExtensions.DeriveLongTermKey(username, realm, password, sha256, key.Slice(0, keyLength));
            return MessageExtensions.VerifyMessageIntegrity(message, key.Slice(0, keyLength), hash);
        }

        private bool HasMatchingRealm(in StunServiceState state)
        {
            var realm = AuthorizationRealm;
            return !state.Realm.IsEmpty && state.Realm.Span.SequenceEqual(realm.Span);
        }

        private static bool IsPasswordAlgorithmPaired(in StunServiceState state)
        {
            if (state.PasswordAlgorithm == MessageExtensions.PasswordAlgorithmSha256)
                return state.MessageIntegrity.Length == 32;
            if (state.PasswordAlgorithm == MessageExtensions.PasswordAlgorithmMd5)
                return state.MessageIntegrity.Length == 20;
            return state.PasswordAlgorithm == 0;
        }

        private static byte[] CreateNonce()
        {
            Span<byte> key = stackalloc byte[16];
            RandomNumberGenerator.Fill(key);
            Span<byte> expiry = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(expiry, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + NonceLifetimeSeconds);
            Span<byte> mac = stackalloc byte[32];
            HMACSHA256.HashData(key, expiry, mac);
            var nonce = new byte[112];
            EncodeHex(key, nonce.AsSpan(0, 32));
            EncodeHex(expiry, nonce.AsSpan(32, 16));
            EncodeHex(mac, nonce.AsSpan(48));
            return nonce;
        }

        private static bool IsNonceCurrent(ReadOnlySpan<byte> nonce)
        {
            if (nonce.Length != 112)
                return false;
            Span<byte> key = stackalloc byte[16];
            Span<byte> expiry = stackalloc byte[8];
            Span<byte> mac = stackalloc byte[32];
            Span<byte> actual = stackalloc byte[32];
            if (!TryDecodeHex(nonce.Slice(0, 32), key) || !TryDecodeHex(nonce.Slice(32, 16), expiry) || !TryDecodeHex(nonce.Slice(48), mac))
                return false;
            HMACSHA256.HashData(key, expiry, actual);
            if (!CryptographicOperations.FixedTimeEquals(mac, actual))
                return false;
            return BinaryPrimitives.ReadInt64BigEndian(expiry) >= DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        private void WriteChallenge(ref Span<byte> buffer, ref int length)
        {
            CreateOpaqueAttribute(ref buffer, MessageAttributeType.Realm, AuthorizationRealm.Span, ref length);
            var nonce = CreateNonce();
            CreateOpaqueAttribute(ref buffer, MessageAttributeType.Nonce, nonce, ref length);
            CreatePasswordAlgorithmsAttribute(ref buffer, ref length);
        }

        private static void SignResponse(Span<byte> response, int integrityOffset, ReadOnlySpan<byte> password, bool longTerm, bool sha256, ReadOnlySpan<byte> username, ReadOnlySpan<byte> realm)
        {
            if (!longTerm)
            {
                MessageExtensions.WriteMessageIntegrity(response, integrityOffset, password, sha256);
                return;
            }
            var keyLength = sha256 ? 32 : 16;
            Span<byte> key = stackalloc byte[32];
            MessageExtensions.DeriveLongTermKey(username, realm, password, sha256, key.Slice(0, keyLength));
            MessageExtensions.WriteMessageIntegrity(response, integrityOffset, key.Slice(0, keyLength), sha256);
        }

        private static void EncodeHex(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            const string Hex = "0123456789abcdef";
            for (var i = 0; i < data.Length; i++)
            {
                destination[i * 2] = (byte)Hex[data[i] >> 4];
                destination[i * 2 + 1] = (byte)Hex[data[i] & 0x0F];
            }
        }

        private static bool TryDecodeHex(ReadOnlySpan<byte> text, Span<byte> destination)
        {
            if (text.Length != destination.Length * 2)
                return false;
            for (var i = 0; i < destination.Length; i++)
            {
                if (!TryHexValue(text[i * 2], out var high) || !TryHexValue(text[i * 2 + 1], out var low))
                    return false;
                destination[i] = (byte)((high << 4) | low);
            }
            return true;
        }

        private static bool TryHexValue(byte value, out int nibble)
        {
            if (value is >= (byte)'0' and <= (byte)'9')
            {
                nibble = value - (byte)'0';
                return true;
            }
            if (value is >= (byte)'a' and <= (byte)'f')
            {
                nibble = value - (byte)'a' + 10;
                return true;
            }
            if (value is >= (byte)'A' and <= (byte)'F')
            {
                nibble = value - (byte)'A' + 10;
                return true;
            }
            nibble = 0;
            return false;
        }

        //rfc3489 11.2.9
        private static void CreateErrorResponseAttribute(ref Span<byte> buffer, ushort code, string message, ref int length)
        {
            var messageLength = Encoding.UTF8.GetByteCount(message);
            if (messageLength > ushort.MaxValue - 4)
                throw new InvalidOperationException("Message data must less than or equal to 65531.");
            var valueLength = 4 + messageLength;
            var paddedLength = (valueLength + 3) & ~3;
            var total = 4 + paddedLength;
            length += total;
            buffer.Slice(0, total).Clear();
            MemoryMarshal.Write(buffer, MessageAttributeType.ErrorCode);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), (ushort)valueLength);
            buffer[6] = (byte)(code / 100);
            buffer[7] = (byte)(code % 100);
            Encoding.UTF8.GetBytes(message, buffer.Slice(8, messageLength));
            buffer = buffer.Slice(total);
        }

        //rfc3489 11.2.10
        private static void CreateUnknownAttributesAttribute(ref Span<byte> buffer, List<ushort> unknownAttributes, ref int length)
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

        private static void CreateMappedAddressAttribute(ref Span<byte> buffer, ReadOnlyMemory<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.MappedAddress, address, port, ref length);
        }

        private static void CreateSourceAddressAttribute(ref Span<byte> buffer, ReadOnlyMemory<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.SourceAddress, address, port, ref length);
        }

        private static void CreateChangedAddressAttribute(ref Span<byte> buffer, ReadOnlyMemory<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.ChangedAddress, address, port, ref length);
        }

        private static void CreateReflectedFromAttribute(ref Span<byte> buffer, ReadOnlyMemory<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.ReflectedFrom, address, port, ref length);
        }

        private static void CreateOtherAddressAttribute(ref Span<byte> buffer, ReadOnlyMemory<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.OtherAddress, address, port, ref length);
        }

        private static void CreateResponseOriginAttribute(ref Span<byte> buffer, ReadOnlyMemory<byte> address, ushort port, ref int length)
        {
            CreateAddressAttribute(ref buffer, MessageAttributeType.ResponseOrigin, address, port, ref length);
        }

        private static void CreatePasswordAlgorithmsAttribute(ref Span<byte> buffer, ref int length)
        {
            length += 12;
            MemoryMarshal.Write(buffer, MessageAttributeType.PasswordAlgorithms);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), 8);
            buffer.Slice(4, 8).Clear();
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(4), MessageExtensions.PasswordAlgorithmSha256);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(8), MessageExtensions.PasswordAlgorithmMd5);
            buffer = buffer.Slice(12);
        }

        private static void CreateOpaqueAttribute(ref Span<byte> buffer, MessageAttributeType attributeType, ReadOnlySpan<byte> value, ref int length)
        {
            var paddedLength = (value.Length + 3) & ~3;
            var total = 4 + paddedLength;
            length += total;
            MemoryMarshal.Write(buffer, attributeType);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), (ushort)value.Length);
            value.CopyTo(buffer.Slice(4));
            if (paddedLength != value.Length)
                buffer.Slice(4 + value.Length, paddedLength - value.Length).Clear();
            buffer = buffer.Slice(total);
        }

        private static void CreateXORMappedAddressAttribute(ref Span<byte> buffer, ReadOnlyMemory<byte> transactionId, ReadOnlyMemory<byte> address, ushort port, ref int length)
        {
            var addressSpan = address.Span;
            int attributeLength;
            if (addressSpan.Length == 4)
                attributeLength = 12;
            else
                attributeLength = 24;
            length += attributeLength;
            MemoryMarshal.Write(buffer, MessageAttributeType.XORMappedAddress);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), (ushort)(attributeLength - 4));
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(6), (ushort)(port ^ 0x2112u));
            if (addressSpan.Length == 4)
                buffer[5] = 1;
            else
                buffer[5] = 2;
            addressSpan.CopyTo(buffer.Slice(8));
            //0x42A41221
            buffer[8] ^= 0x21;
            buffer[9] ^= 0x12;
            buffer[10] ^= 0xA4;
            buffer[11] ^= 0x42;
            if (addressSpan.Length != 4)
            {
                var transactionIdSpan = transactionId.Span;
                for (int i = 0; i < 12; i++)
                {
                    buffer[12 + i] ^= transactionIdSpan[i];
                }
            }
            buffer = buffer.Slice(attributeLength);
        }

        private static void CreateAddressAttribute(ref Span<byte> buffer, MessageAttributeType attributeType, ReadOnlyMemory<byte> address, ushort port, ref int length)
        {
            var addressSpan = address.Span;
            int attributeLength;
            if (addressSpan.Length == 4)
                attributeLength = 12;
            else
                attributeLength = 24;
            length += attributeLength;
            MemoryMarshal.Write(buffer, attributeType);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(2), (ushort)(attributeLength - 4));
            BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(6), (ushort)port);
            if (addressSpan.Length == 4)
                buffer[5] = 1;
            else
                buffer[5] = 2;
            addressSpan.CopyTo(buffer.Slice(8));
            buffer = buffer.Slice(attributeLength);
        }
    }
}
