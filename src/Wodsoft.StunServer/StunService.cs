using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Wodsoft.StunServer
{
    public class StunService
    {
        private List<Task>? _tasks;

        public Task<bool> RunAsync(Config config, ILogger logger, CancellationToken cancellationToken)
        {
            if (Start(config, logger, cancellationToken))
                return Task.WhenAll(_tasks!).ContinueWith(task => true);
            return Task.FromResult(false);
        }

        public bool Start(Config config, ILogger logger, CancellationToken cancellationToken)
        {
            List<Task> tasks = new List<Task>();
            if (config.EnableIPv4)
            {
                var primaryAddress = IPAddress.Parse(config.PrimaryIPv4Address!);
                IPAddress localPrimaryAddress = config.LocalPrimaryIPv4Address == null ? primaryAddress : IPAddress.Parse(config.LocalPrimaryIPv4Address);
                if (config.EnableUDP)
                {
                    var secondaryAddress = IPAddress.Parse(config.SecondaryIPv4Address!);
                    if (config.EnableUDPProxy)
                    {
                        if (!CreateUDPWithProxy(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                            localPrimaryAddress, config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                            IPAddress.Parse(config.ProxyLocalIPv4Address!), config.ProxyLocalIPv4Port, new IPEndPoint(IPAddress.Parse(config.ProxyRemoteIPv4Address!), config.ProxyRemoteIPv4Port),
                            tasks, logger, cancellationToken))
                            return false;
                    }
                    else
                    {
                        IPAddress? localSecondaryAddress = config.LocalSecondaryIPv4Address == null ? secondaryAddress : IPAddress.Parse(config.LocalSecondaryIPv4Address);
                        if (!CreateUDP(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                            localPrimaryAddress, localSecondaryAddress,
                            config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                            tasks, logger, cancellationToken))
                            return false;
                    }
                }
                if (config.EnableTCP)
                    if (!CreateTCP(primaryAddress, config.PrimaryPort,
                        localPrimaryAddress, config.LocalPrimaryPort ?? config.PrimaryPort,
                        tasks, logger, cancellationToken))
                        return false;
                if (config.EnableTLS)
                {
                    var certificate = X509Certificate2.CreateFromPemFile(config.CertificateFile!);
                    certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
                    if (!CreateTLS(primaryAddress, config.TLSPrimaryPort,
                        localPrimaryAddress, config.LocalTLSPrimaryPort ?? config.TLSPrimaryPort,
                        tasks, certificate, logger, cancellationToken))
                        return false;
                }
            }
            if (config.EnableIPv6)
            {
                var primaryAddress = IPAddress.Parse(config.PrimaryIPv6Address!);
                IPAddress localPrimaryAddress = config.LocalPrimaryIPv6Address == null ? primaryAddress : IPAddress.Parse(config.LocalPrimaryIPv6Address);
                if (config.EnableUDP)
                {
                    var secondaryAddress = IPAddress.Parse(config.SecondaryIPv6Address!);
                    if (config.EnableUDPProxy)
                    {
                        if (!CreateUDPWithProxy(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                            localPrimaryAddress, config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                            IPAddress.Parse(config.ProxyLocalIPv6Address!), config.ProxyLocalIPv6Port, new IPEndPoint(IPAddress.Parse(config.ProxyRemoteIPv6Address!), config.ProxyRemoteIPv6Port),
                            tasks, logger, cancellationToken))
                            return false;
                    }
                    else
                    {
                        IPAddress localSecondaryAddress = config.LocalSecondaryIPv6Address == null ? secondaryAddress : IPAddress.Parse(config.LocalSecondaryIPv6Address);
                        if (!CreateUDP(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                            localPrimaryAddress, localSecondaryAddress,
                            config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                            tasks, logger, cancellationToken))
                            return false;
                    }
                }
                if (config.EnableTCP)
                    if (!CreateTCP(primaryAddress, config.PrimaryPort,
                        localPrimaryAddress, config.LocalPrimaryPort ?? config.PrimaryPort,
                        tasks, logger, cancellationToken))
                        return false;
                if (config.EnableTLS)
                {
                    var certificate = X509Certificate2.CreateFromPemFile(config.CertificateFile!);
                    certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
                    if (!CreateTLS(primaryAddress, config.TLSPrimaryPort,
                        localPrimaryAddress, config.LocalTLSPrimaryPort ?? config.TLSPrimaryPort,
                        tasks, certificate, logger, cancellationToken))
                        return false;
                }
            }
            _tasks = tasks;
            return true;
        }

        public Task StopAsync()
        {
            return Task.WhenAll(_tasks!);
        }

        private bool CreateUDP(IPAddress primaryAddress, IPAddress secondaryAddress, ushort primaryPort, ushort secondaryPort,
            IPAddress localPrimaryAddress, IPAddress localSecondaryAddress, ushort localPrimaryPort, ushort localSecondaryPort,
            List<Task> tasks, ILogger logger, CancellationToken cancellationToken)
        {
            var a1p1Socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                a1p1Socket.Bind(new IPEndPoint(localPrimaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind UDP primary address {localPrimaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind UDP primary address {localPrimaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }
            var a1p2Socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                a1p2Socket.Bind(new IPEndPoint(localPrimaryAddress, localSecondaryPort));
                logger.LogInformation($"Bind UDP primary address {localPrimaryAddress} secondary port {localSecondaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind UDP primary address {localPrimaryAddress} secondary port {localSecondaryPort} failed.");
                return false;
            }
            var a2p1Socket = new Socket(localSecondaryAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                a2p1Socket.Bind(new IPEndPoint(localSecondaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind UDP secondary address {localSecondaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind UDP secondary address {localSecondaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }
            var a2p2Socket = new Socket(localSecondaryAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                a2p2Socket.Bind(new IPEndPoint(localSecondaryAddress, localSecondaryPort));
                logger.LogInformation($"Bind UDP secondary address {localSecondaryAddress} secondary port {localSecondaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind UDP secondary address {localSecondaryAddress} secondary port {localSecondaryPort} failed.");
                return false;
            }
            StunUdpService udpService1 = new StunUdpService(new StunUdpServiceOptions(primaryAddress, primaryPort, secondaryAddress, secondaryPort,
                new StunUdpSocket(a1p1Socket), new StunUdpSocket(a1p2Socket),
                new StunUdpSocket(a2p1Socket), new StunUdpSocket(a2p2Socket)), logger);
            StunUdpService udpService2 = new StunUdpService(new StunUdpServiceOptions(primaryAddress, secondaryPort, secondaryAddress, primaryPort,
                new StunUdpSocket(a1p2Socket), new StunUdpSocket(a1p1Socket),
                new StunUdpSocket(a2p2Socket), new StunUdpSocket(a2p1Socket)), logger);
            StunUdpService udpService3 = new StunUdpService(new StunUdpServiceOptions(secondaryAddress, primaryPort, primaryAddress, secondaryPort,
                new StunUdpSocket(a2p1Socket), new StunUdpSocket(a2p2Socket),
                new StunUdpSocket(a1p1Socket), new StunUdpSocket(a1p2Socket)), logger);
            StunUdpService udpService4 = new StunUdpService(new StunUdpServiceOptions(secondaryAddress, secondaryPort, primaryAddress, primaryPort,
                new StunUdpSocket(a2p2Socket), new StunUdpSocket(a2p1Socket),
                new StunUdpSocket(a1p2Socket), new StunUdpSocket(a1p1Socket)), logger);
            tasks.Add(udpService1.RunAsync(cancellationToken));
            tasks.Add(udpService2.RunAsync(cancellationToken));
            tasks.Add(udpService3.RunAsync(cancellationToken));
            tasks.Add(udpService4.RunAsync(cancellationToken));
            return true;
        }

        private bool CreateUDPWithProxy(IPAddress primaryAddress, IPAddress secondaryAddress, ushort primaryPort, ushort secondaryPort,
            IPAddress localPrimaryAddress, ushort localPrimaryPort, ushort localSecondaryPort,
            IPAddress proxyLocalAddress, ushort proxylocalPort, IPEndPoint proxyRemoteEndPoint,
            List<Task> tasks, ILogger logger, CancellationToken cancellationToken)
        {
            var a1p1Socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                a1p1Socket.Bind(new IPEndPoint(localPrimaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind UDP primary address {localPrimaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind UDP primary address {localPrimaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }
            var a1p2Socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                a1p2Socket.Bind(new IPEndPoint(localPrimaryAddress, localSecondaryPort));
                logger.LogInformation($"Bind UDP primary address {localPrimaryAddress} secondary port {localSecondaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind UDP primary address {localPrimaryAddress} secondary port {localSecondaryPort} failed.");
                return false;
            }
            var proxySocket = new Socket(proxyLocalAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                proxySocket.Bind(new IPEndPoint(proxyLocalAddress, proxylocalPort));
                logger.LogInformation($"Bind UDP proxy address {proxyLocalAddress} port {proxylocalPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind UDP proxy address {proxyLocalAddress} port {proxylocalPort} failed.");
                return false;
            }
            StunUdpProxy proxy = new StunUdpProxy(new StunUdpProxyOptions(a1p1Socket, a1p2Socket, proxySocket, proxyRemoteEndPoint), logger);
            StunUdpService udpService1 = new StunUdpService(new StunUdpServiceOptions(primaryAddress, primaryPort, secondaryAddress, secondaryPort,
                new StunUdpSocket(a1p1Socket), new StunUdpSocket(a1p2Socket),
                proxy.PrimaryPortSocket, proxy.SecondaryPortSocket), logger);
            StunUdpService udpService2 = new StunUdpService(new StunUdpServiceOptions(primaryAddress, secondaryPort, secondaryAddress, primaryPort,
                new StunUdpSocket(a1p2Socket), new StunUdpSocket(a1p1Socket),
                proxy.SecondaryPortSocket, proxy.PrimaryPortSocket), logger);
            tasks.Add(proxy.RunAsync(cancellationToken));
            tasks.Add(udpService1.RunAsync(cancellationToken));
            tasks.Add(udpService2.RunAsync(cancellationToken));
            return true;
        }

        private bool CreateTCP(IPAddress primaryAddress, ushort primaryPort,
            IPAddress localPrimaryAddress, ushort localPrimaryPort,
            List<Task> tasks, ILogger logger, CancellationToken cancellationToken)
        {
            var socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Bind(new IPEndPoint(localPrimaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind TCP primary address {localPrimaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TCP primary address {localPrimaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }

            tasks.Add(new StunTcpService(new StunTcpServiceOptions(primaryAddress, primaryPort, primaryAddress, primaryPort, socket), logger).RunAsync(cancellationToken));
            return true;
        }

        private bool CreateTLS(IPAddress primaryAddress, ushort primaryPort,
            IPAddress localPrimaryAddress, ushort localPrimaryPort,
            List<Task> tasks, X509Certificate2 certificate, ILogger logger, CancellationToken cancellationToken)
        {
            var socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Bind(new IPEndPoint(localPrimaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind TLS primary address {localPrimaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TLS primary address {localPrimaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }

            tasks.Add(new StunTlsService(new StunTlsServiceOptions(primaryAddress, primaryPort, primaryAddress, primaryPort, socket, certificate), logger).RunAsync(cancellationToken));
            return true;
        }
    }
}
