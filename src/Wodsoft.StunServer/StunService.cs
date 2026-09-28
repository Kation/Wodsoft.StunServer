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
                var secondaryAddress = IPAddress.Parse(config.SecondaryIPv4Address!);
                IPAddress localPrimaryAddress = config.LocalPrimaryIPv4Address == null ? primaryAddress : IPAddress.Parse(config.LocalPrimaryIPv4Address);
                IPAddress localSecondaryAddress = config.LocalSecondaryIPv4Address == null ? secondaryAddress : IPAddress.Parse(config.LocalSecondaryIPv4Address);
                if (config.EnableUDP)
                    if (!CreateUDP(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                        localPrimaryAddress, localSecondaryAddress,
                        config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                        tasks, logger, cancellationToken))
                        return false;
                if (config.EnableTCP)
                    if (!CreateTCP(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                        localPrimaryAddress, localSecondaryAddress,
                        config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                        tasks, logger, cancellationToken))
                        return false;
                if (config.EnableTLS)
                {
                    var certificate = X509Certificate2.CreateFromPemFile(config.CertificateFile!);
                    certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
                    if (!CreateTLS(primaryAddress, secondaryAddress, config.TLSPrimaryPort, config.TLSSecondaryPort,
                        localPrimaryAddress, localSecondaryAddress,
                        config.LocalTLSPrimaryPort ?? config.TLSPrimaryPort, config.LocalTLSSecondaryPort ?? config.TLSSecondaryPort,
                        tasks, certificate, logger, cancellationToken))
                        return false;
                }
            }
            if (config.EnableIPv6)
            {
                var primaryAddress = IPAddress.Parse(config.PrimaryIPv6Address!);
                var secondaryAddress = IPAddress.Parse(config.SecondaryIPv6Address!);
                IPAddress localPrimaryAddress = config.LocalPrimaryIPv6Address == null ? primaryAddress : IPAddress.Parse(config.LocalPrimaryIPv6Address);
                IPAddress localSecondaryAddress = config.LocalSecondaryIPv6Address == null ? secondaryAddress : IPAddress.Parse(config.LocalSecondaryIPv6Address);
                if (config.EnableUDP)
                    if (!CreateUDP(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                        localPrimaryAddress, localSecondaryAddress,
                        config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                        tasks, logger, cancellationToken))
                        return false;
                if (config.EnableTCP)
                    if (!CreateTCP(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                        localPrimaryAddress, localSecondaryAddress,
                        config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                        tasks, logger, cancellationToken))
                        return false;
                if (config.EnableTLS)
                {
                    var certificate = X509Certificate2.CreateFromPemFile(config.CertificateFile!);
                    certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
                    if (!CreateTLS(primaryAddress, secondaryAddress, config.TLSPrimaryPort, config.TLSSecondaryPort,
                        localPrimaryAddress, localSecondaryAddress,
                        config.LocalTLSPrimaryPort ?? config.TLSPrimaryPort, config.LocalTLSSecondaryPort ?? config.TLSSecondaryPort,
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
            StunUdpService udpService2 = new StunUdpService(new StunUdpServiceOptions(primaryAddress, primaryPort, secondaryAddress, secondaryPort,
                new StunUdpSocket(a1p2Socket), new StunUdpSocket(a1p1Socket),
                new StunUdpSocket(a2p2Socket), new StunUdpSocket(a2p1Socket)), logger);
            StunUdpService udpService3 = new StunUdpService(new StunUdpServiceOptions(primaryAddress, primaryPort, secondaryAddress, secondaryPort,
                new StunUdpSocket(a2p1Socket), new StunUdpSocket(a2p2Socket),
                new StunUdpSocket(a1p1Socket), new StunUdpSocket(a1p2Socket)), logger);
            StunUdpService udpService4 = new StunUdpService(new StunUdpServiceOptions(primaryAddress, primaryPort, secondaryAddress, secondaryPort,
                new StunUdpSocket(a2p2Socket), new StunUdpSocket(a2p1Socket),
                new StunUdpSocket(a1p2Socket), new StunUdpSocket(a1p1Socket)), logger);
            tasks.Add(udpService1.RunAsync(cancellationToken));
            tasks.Add(udpService2.RunAsync(cancellationToken));
            tasks.Add(udpService3.RunAsync(cancellationToken));
            tasks.Add(udpService4.RunAsync(cancellationToken));

            return true;
        }

        private bool CreateTCP(IPAddress primaryAddress, IPAddress secondaryAddress, ushort primaryPort, ushort secondaryPort,
            IPAddress localPrimaryAddress, IPAddress localSecondaryAddress, ushort localPrimaryPort, ushort localSecondaryPort,
            List<Task> tasks, ILogger logger, CancellationToken cancellationToken)
        {
            var a1p1Socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                a1p1Socket.Bind(new IPEndPoint(localPrimaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind TCP primary address {localPrimaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TCP primary address {localPrimaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }
            var a1p2Socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                a1p2Socket.Bind(new IPEndPoint(localPrimaryAddress, localSecondaryPort));
                logger.LogInformation($"Bind TCP primary address {localPrimaryAddress} secondary port {localSecondaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TCP primary address {localPrimaryAddress} secondary port {localSecondaryPort} failed.");
                return false;
            }
            var a2p1Socket = new Socket(localSecondaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                a2p1Socket.Bind(new IPEndPoint(localSecondaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind TCP secondary address {localSecondaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TCP secondary address {localSecondaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }
            var a2p2Socket = new Socket(localSecondaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                a2p2Socket.Bind(new IPEndPoint(localSecondaryAddress, localSecondaryPort));
                logger.LogInformation($"Bind TCP secondary address {localSecondaryAddress} secondary port {localSecondaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TCP secondary address {localSecondaryAddress} secondary port {localSecondaryPort} failed.");
                return false;
            }

            tasks.Add(new StunTcpService(new StunTcpServiceOptions(primaryAddress, primaryPort, secondaryAddress, secondaryPort, a1p1Socket), logger).RunAsync(cancellationToken));
            tasks.Add(new StunTcpService(new StunTcpServiceOptions(primaryAddress, secondaryPort, secondaryAddress, primaryPort, a1p2Socket), logger).RunAsync(cancellationToken));
            tasks.Add(new StunTcpService(new StunTcpServiceOptions(secondaryAddress, primaryPort, primaryAddress, secondaryPort, a2p1Socket), logger).RunAsync(cancellationToken));
            tasks.Add(new StunTcpService(new StunTcpServiceOptions(secondaryAddress, secondaryPort, primaryAddress, primaryPort, a2p2Socket), logger).RunAsync(cancellationToken));

            return true;
        }

        private bool CreateTLS(IPAddress primaryAddress, IPAddress secondaryAddress, ushort primaryPort, ushort secondaryPort,
            IPAddress localPrimaryAddress, IPAddress localSecondaryAddress, ushort localPrimaryPort, ushort localSecondaryPort,
            List<Task> tasks, X509Certificate2 certificate, ILogger logger, CancellationToken cancellationToken)
        {
            var a1p1Socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                a1p1Socket.Bind(new IPEndPoint(localPrimaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind TLS primary address {localPrimaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TLS primary address {localPrimaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }
            var a1p2Socket = new Socket(localPrimaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                a1p2Socket.Bind(new IPEndPoint(localPrimaryAddress, localSecondaryPort));
                logger.LogInformation($"Bind TLS primary address {localPrimaryAddress} secondary port {localSecondaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TLS primary address {localPrimaryAddress} secondary port {localSecondaryPort} failed.");
                return false;
            }
            var a2p1Socket = new Socket(localSecondaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                a2p1Socket.Bind(new IPEndPoint(localSecondaryAddress, localPrimaryPort));
                logger.LogInformation($"Bind TLS secondary address {localSecondaryAddress} primary port {localPrimaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TLS secondary address {localSecondaryAddress} primary port {localPrimaryPort} failed.");
                return false;
            }
            var a2p2Socket = new Socket(localSecondaryAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                a2p2Socket.Bind(new IPEndPoint(localSecondaryAddress, localSecondaryPort));
                logger.LogInformation($"Bind TLS secondary address {localSecondaryAddress} secondary port {localSecondaryPort} successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Bind TLS secondary address {localSecondaryAddress} secondary port {localSecondaryPort} failed.");
                return false;
            }

            tasks.Add(new StunTlsService(new StunTlsServiceOptions(primaryAddress, primaryPort, secondaryAddress, secondaryPort, a1p1Socket, certificate), logger).RunAsync(cancellationToken));
            tasks.Add(new StunTlsService(new StunTlsServiceOptions(primaryAddress, secondaryPort, secondaryAddress, primaryPort, a1p2Socket, certificate), logger).RunAsync(cancellationToken));
            tasks.Add(new StunTlsService(new StunTlsServiceOptions(secondaryAddress, primaryPort, primaryAddress, secondaryPort, a2p1Socket, certificate), logger).RunAsync(cancellationToken));
            tasks.Add(new StunTlsService(new StunTlsServiceOptions(secondaryAddress, secondaryPort, primaryAddress, primaryPort, a2p2Socket, certificate), logger).RunAsync(cancellationToken));

            return true;
        }
    }
}
