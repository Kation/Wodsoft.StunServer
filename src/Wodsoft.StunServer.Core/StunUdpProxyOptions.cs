using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Wodsoft.StunServer
{
    public class StunUdpProxyOptions
    {
        public StunUdpProxyOptions(Socket primaryPortSocket, Socket secondaryPortSocket, Socket proxySocket, IPEndPoint proxyEndPoint)
        {
            PrimaryPortSocket = primaryPortSocket;
            SecondaryPortSocket = secondaryPortSocket;
            ProxySocket = proxySocket;
            ProxyEndPoint = proxyEndPoint;
        }

        public Socket PrimaryPortSocket { get; }
        
        public Socket SecondaryPortSocket { get; }

        public Socket ProxySocket { get; }

        public IPEndPoint ProxyEndPoint { get; set; }
    }
}
