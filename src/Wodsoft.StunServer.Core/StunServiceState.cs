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
        public bool HasMessageIntegrity;
    }
}
