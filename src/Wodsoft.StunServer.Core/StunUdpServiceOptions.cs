using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Wodsoft.StunServer
{
    public class StunUdpServiceOptions
    {
        public StunUdpServiceOptions(IPAddress primaryAddress, ushort primaryPort, IPAddress secondaryAddress, ushort secondaryPort, 
            IStunUdpSocket primaryAddressPrimaryPortSocket, IStunUdpSocket primaryAddressSecondaryPortSocket, 
            IStunUdpSocket secondaryAddressPrimaryPortSocket, IStunUdpSocket secondaryAddressSecondaryPortSocket)
        {
            PrimaryAddress = primaryAddress;
            PrimaryPort = primaryPort;
            SecondaryAddress = secondaryAddress;
            SecondaryPort = secondaryPort;
            PrimaryAddressPrimaryPortSocket = primaryAddressPrimaryPortSocket;
            PrimaryAddressSecondaryPortSocket = primaryAddressSecondaryPortSocket;
            SecondaryAddressPrimaryPortSocket = secondaryAddressPrimaryPortSocket;
            SecondaryAddressSecondaryPortSocket = secondaryAddressSecondaryPortSocket;
        }

        public IPAddress PrimaryAddress { get; }

        public ushort PrimaryPort { get; }

        public IPAddress SecondaryAddress { get; }

        public ushort SecondaryPort { get; }

        public IStunUdpSocket PrimaryAddressPrimaryPortSocket { get; }

        public IStunUdpSocket PrimaryAddressSecondaryPortSocket { get; }

        public IStunUdpSocket SecondaryAddressPrimaryPortSocket { get; }

        public IStunUdpSocket SecondaryAddressSecondaryPortSocket { get; }

        public int ProcessThreads { get; set; } = Environment.ProcessorCount;
    }
}
