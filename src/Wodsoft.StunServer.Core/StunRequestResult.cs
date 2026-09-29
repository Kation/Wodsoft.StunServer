using System;
using System.Collections.Generic;
using System.Text;

namespace Wodsoft.StunServer
{
    public struct StunRequestResult
    {
        public byte[]? Response;
        public int ResponseLength;
        public ReadOnlyMemory<byte> ResponseAddress;
        public ushort ResponsePort;
        public bool ChangeAddress;
        public bool ChangePort;
    }
}
