using System.Net;
using System.Net.Sockets;

namespace Wodsoft.StunServer
{
    public class StunTcpServiceOptions
    {
        public StunTcpServiceOptions(IPAddress primaryAddress, ushort primaryPort, IPAddress secondaryAddress, ushort secondaryPort, Socket socket)
        {
            PrimaryAddress = primaryAddress;
            PrimaryPort = primaryPort;
            SecondaryAddress = secondaryAddress;
            SecondaryPort = secondaryPort;
            Socket = socket;
        }

        public IPAddress PrimaryAddress { get; }

        public ushort PrimaryPort { get; }

        public IPAddress SecondaryAddress { get; }

        public ushort SecondaryPort { get; }

        public Socket Socket { get; }
    }
}
