using System;
using System.Collections.Generic;
using System.Text;

namespace Wodsoft.StunServer
{
    public struct StunServiceState
    {
        public ReadOnlyMemory<byte> ReplyAddress;
        public ushort ReplyPort;
        public bool ChangeAddress;
        public bool ChangePort;
        public ReadOnlyMemory<byte> UserName;
        public ReadOnlyMemory<byte> Realm;
        public ReadOnlyMemory<byte> Nonce;
        public ushort PasswordAlgorithm;
        public int MessageIntegrityOffset;
        public ReadOnlyMemory<byte> MessageIntegrity;
    }
}
