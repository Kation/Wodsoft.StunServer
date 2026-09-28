using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.StunServer
{
    [StructLayout(LayoutKind.Explicit, Size = 8)]
    public struct MessageHeader
    {
        public MessageHeader(MessageType messageType, ushort messageLength)
        {
            MessageType = messageType;
            MessageLength = messageLength;
            MagicCookie = 0x42A41221u;
        }

        [FieldOffset(0)]
        public MessageType MessageType;

        [FieldOffset(2)]
        private ushort _messageLength;

        public ushort MessageLength { get => BinaryPrimitives.ReverseEndianness(_messageLength); set => _messageLength = BinaryPrimitives.ReverseEndianness(value); }

        [FieldOffset(4)]
        public uint MagicCookie;
    }
}
