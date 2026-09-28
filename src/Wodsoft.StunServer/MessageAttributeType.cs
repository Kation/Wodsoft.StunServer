using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.StunServer
{
    public enum MessageAttributeType : ushort
    {
        MappedAddress = 0x0100,//1
        ResponseAddress = 0x0200,//2
        ChangeRequest = 0x0300,//3
        SourceAddress = 0x0400,//4
        ChangedAddress = 0x0500,//5
        UserName = 0x0600,//6
        Password = 0x0700,//7
        MessageIntegrity = 0x0800,//8
        ErrorCode = 0x0900,//9
        Unknown = 0x0A00,//10
        ReflectedFrom = 0x0B00,//11
        Realm = 0x1400,
        Nonce = 0x1500,
        XORMappedAddress = 0x2000,//32
        Padding = 0x2600,
        ResponsePort = 0x2700,
        ResponseOrigin = 0x2B80,
        OtherAddress = 0x2C80
    }
}
