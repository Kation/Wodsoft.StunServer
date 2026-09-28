using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.StunServer
{
    public enum MessageType : ushort
    {
        Request = 0x0100,//0x0001
        Response = 0x0101,//0x0101
        Error = 0x1101//0x0111
    }
}
