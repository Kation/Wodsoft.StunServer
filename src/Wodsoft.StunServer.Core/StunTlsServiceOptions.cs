using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Wodsoft.StunServer
{
    public class StunTlsServiceOptions
    {
        public StunTlsServiceOptions(IPAddress primaryAddress, ushort primaryPort, IPAddress secondaryAddress, ushort secondaryPort, Socket socket, X509Certificate2 certificate)
        {
            PrimaryAddress = primaryAddress;
            PrimaryPort = primaryPort;
            SecondaryAddress = secondaryAddress;
            SecondaryPort = secondaryPort;
            Socket = socket;
            Certificate = certificate;
        }

        public IPAddress PrimaryAddress { get; }

        public ushort PrimaryPort { get; }

        public IPAddress SecondaryAddress { get; }

        public ushort SecondaryPort { get; }

        public Socket Socket { get; }

        public X509Certificate2 Certificate { get; }
    }
}
