using System;
using System.Buffers;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

namespace Wodsoft.StunServer.Commands
{
    public class RunCommand : Command
    {
        public RunCommand() : base("run", "Run stun server.")
        {
            var verbosityOption = new Option<LogLevel>("--verbosity", "Logging verbosity.");
            verbosityOption.AddAlias("-v");
            verbosityOption.Arity = ArgumentArity.ExactlyOne;
#if DEBUG
            verbosityOption.SetDefaultValue(LogLevel.Information);
#else
            verbosityOption.SetDefaultValue(LogLevel.Warning);
#endif
            AddOption(verbosityOption);
            this.SetHandler(RunAsync, verbosityOption);
        }

        private async Task RunAsync(LogLevel logLevel)
        {
            Config config;
            if (!File.Exists("config.json"))
            {
                Console.WriteLine("Configuration file config.json not exists.");
                return;
            }
            else
            {
                Stream stream;
                try
                {
                    stream = File.OpenRead("config.json");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Read configuration file failed: {ex.Message}");
                    return;
                }
                config = await JsonSerializer.DeserializeAsync<Config>(stream, SourceGenerationContext.Default.Options) ?? new Config();
            }
            if (!config.Validate())
                return;

            CancellationTokenSource cts = new CancellationTokenSource();
            var primaryAddress = IPAddress.Parse(config.PrimaryIPv4Address!);
            var secondaryAddress = IPAddress.Parse(config.SecondaryIPv4Address!);
            IPAddress localPrimaryAddress = config.LocalPrimaryIPv4Address == null ? primaryAddress : IPAddress.Parse(config.LocalPrimaryIPv4Address);
            IPAddress localSecondaryAddress = config.LocalSecondaryIPv4Address == null ? secondaryAddress : IPAddress.Parse(config.LocalSecondaryIPv4Address);
            List<Task<bool>> tasks = new List<Task<bool>>();
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(logLevel).AddConsole();
#if DEBUG
                builder.AddDebug();
#endif
            });
            var logger = loggerFactory.CreateLogger<RunCommand>();
            if (config.EnableUDP)
                tasks.Add(CreateUDP(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                    localPrimaryAddress, localSecondaryAddress,
                    config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                    logger, cts.Token));
            if (config.EnableTCP)
                tasks.Add(CreateTCP(primaryAddress, secondaryAddress, config.PrimaryPort, config.SecondaryPort,
                    localPrimaryAddress, localSecondaryAddress,
                    config.LocalPrimaryPort ?? config.PrimaryPort, config.LocalSecondaryPort ?? config.SecondaryPort,
                    logger, cts.Token));
            if (config.EnableTLS)
            {
                var certificate = X509Certificate2.CreateFromPemFile(config.CertificateFile!);
                certificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable);
                tasks.Add(CreateTLS(primaryAddress, secondaryAddress, config.TLSPrimaryPort, config.TLSSecondaryPort,
                    localPrimaryAddress, localSecondaryAddress,
                    config.LocalTLSPrimaryPort ?? config.TLSPrimaryPort, config.LocalTLSSecondaryPort ?? config.TLSSecondaryPort,
                    certificate, logger, cts.Token));
            }
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };
            var completedTask = await Task.WhenAny(tasks).ConfigureAwait(false);
            if (!completedTask.Result)
            {
                cts.Cancel();
            }
        }

        private async Task<bool> CreateUDP(IPAddress primaryAddress, IPAddress secondaryAddress, int primaryPort, int secondaryPort, IPAddress localPrimaryAddress, IPAddress localSecondaryAddress, int localPrimaryPort, int localSecondaryPort, ILogger logger, CancellationToken cancellationToken)
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
            Task[] tasks =
            [
                ListenUDP(a1p1Socket, a1p2Socket, a2p1Socket, a2p2Socket, primaryAddress, primaryPort, secondaryAddress, secondaryPort, logger, cancellationToken),
                ListenUDP(a1p2Socket, a1p1Socket, a2p2Socket, a2p1Socket, primaryAddress, secondaryPort, secondaryAddress, primaryPort, logger, cancellationToken),
                ListenUDP(a2p1Socket, a2p2Socket, a1p1Socket, a1p2Socket, secondaryAddress, primaryPort, primaryAddress, secondaryPort, logger, cancellationToken),
                ListenUDP(a2p2Socket, a2p1Socket, a1p2Socket, a1p1Socket, secondaryAddress, secondaryPort, primaryAddress, primaryPort, logger, cancellationToken),
            ];
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return true;
        }

        private async Task ListenUDP(Socket thisAddressThisPortSocket, Socket thisAddressOtherPortSocket, Socket otherAddressThisPortSocket, Socket otherAddressOtherPortSocket,
            IPAddress thisAddress, int thisPort, IPAddress otherAddress, int otherPort,
            ILogger logger, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var memory = MemoryPool<byte>.Shared.Rent(1240);
                var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                SocketReceiveFromResult result;
                try
                {
                    result = await thisAddressThisPortSocket.ReceiveFromAsync(memory.Memory, remoteEndPoint, cancellationToken).ConfigureAwait(false);
                    logger.LogDebug($"Receive UDP request from {result.RemoteEndPoint}");
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                if (result.ReceivedBytes < 20)
                    continue;
                _ = Task.Run(async () =>
                {
                    IPEndPoint endPoint = (IPEndPoint)result.RemoteEndPoint;
                    IMemoryOwner<byte>? response;
                    bool changeAddress, changePort;
                    int responseLength;
                    using (memory)
                    {
                        try
                        {
                            response = HandleRequest(memory.Memory.Span, result.ReceivedBytes, ref endPoint, thisAddress, thisPort, otherAddress, otherPort, out changeAddress, out changePort, out responseLength);
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "Handle request failed.");
                            return;
                        }
                    }
                    if (response != null)
                    {
                        using (response)
                        {
                            try
                            {
                                if (!changeAddress && !changePort)
                                    await thisAddressThisPortSocket.SendToAsync(response.Memory.Slice(0, responseLength), endPoint, cancellationToken).ConfigureAwait(false);
                                else if (changeAddress && !changePort)
                                    await otherAddressThisPortSocket.SendToAsync(response.Memory.Slice(0, responseLength), endPoint, cancellationToken).ConfigureAwait(false);
                                else if (changeAddress && changePort)
                                    await otherAddressOtherPortSocket.SendToAsync(response.Memory.Slice(0, responseLength), endPoint, cancellationToken).ConfigureAwait(false);
                                else
                                    await thisAddressOtherPortSocket.SendToAsync(response.Memory.Slice(0, responseLength), endPoint, cancellationToken).ConfigureAwait(false);
                            }
                            catch (Exception ex)
                            {
                                logger.LogDebug(ex, $"Send response to {result.RemoteEndPoint} failed");
                            }
                        }
                    }
                    else
                    {
                        logger.LogDebug($"Bad request from {result.RemoteEndPoint}");
                    }
                });
            }
        }

        private async Task<bool> CreateTCP(IPAddress primaryAddress, IPAddress secondaryAddress, int primaryPort, int secondaryPort, IPAddress localPrimaryAddress, IPAddress localSecondaryAddress, int localPrimaryPort, int localSecondaryPort, ILogger logger, CancellationToken cancellationToken)
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
            Task[] tasks =
            [
                ListenTCP(a1p1Socket, a1p2Socket, a2p1Socket, a2p2Socket, primaryAddress, primaryPort, secondaryAddress, secondaryPort, logger, cancellationToken),
                ListenTCP(a1p2Socket, a1p1Socket, a2p2Socket, a2p1Socket, primaryAddress, secondaryPort, secondaryAddress, primaryPort, logger, cancellationToken),
                ListenTCP(a2p1Socket, a2p2Socket, a1p1Socket, a1p2Socket, secondaryAddress, primaryPort, primaryAddress, secondaryPort, logger, cancellationToken),
                ListenTCP(a2p2Socket, a2p1Socket, a1p2Socket, a1p1Socket, secondaryAddress, secondaryPort, primaryAddress, primaryPort, logger, cancellationToken),
            ];
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return true;
        }

        private async Task ListenTCP(Socket thisAddressThisPortSocket, Socket thisAddressOtherPortSocket, Socket otherAddressThisPortSocket, Socket otherAddressOtherPortSocket,
            IPAddress thisAddress, int thisPort, IPAddress otherAddress, int otherPort,
            ILogger logger, CancellationToken cancellationToken)
        {
            thisAddressThisPortSocket.Listen();
            while (!cancellationToken.IsCancellationRequested)
            {
                var memory = MemoryPool<byte>.Shared.Rent(1240);
                var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                Socket clientSocket;
                try
                {
                    clientSocket = await thisAddressThisPortSocket.AcceptAsync(cancellationToken).ConfigureAwait(false);
                    logger.LogDebug($"Accept TCP request from {clientSocket.RemoteEndPoint}");
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                CancellationTokenSource timeoutTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                int receivedBytes;
                _ = Task.Delay(5000).ContinueWith(task => timeoutTokenSource.Cancel());
                try
                {                    
                    receivedBytes = await clientSocket.ReceiveAsync(memory.Memory, timeoutTokenSource.Token).ConfigureAwait(false);
                }
                catch
                {
                    clientSocket.Dispose();
                    continue;
                }
                if (receivedBytes < 20)
                {
                    try
                    {
                        await clientSocket.DisconnectAsync(false, cancellationToken).ConfigureAwait(false);
                        clientSocket.Dispose();
                    }
                    catch
                    {

                    }
                    continue;
                }
                _ = Task.Run(async () =>
                {
                    IPEndPoint endPoint = (IPEndPoint)clientSocket.RemoteEndPoint!;
                    IMemoryOwner<byte>? response;
                    bool changeAddress, changePort;
                    int responseLength;
                    using (memory)
                    {
                        try
                        {
                            response = HandleRequest(memory.Memory.Span, receivedBytes, ref endPoint, thisAddress, thisPort, otherAddress, otherPort, out changeAddress, out changePort, out responseLength);
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "Handle request failed.");
                            return;
                        }
                    }
                    try
                    {
                        if (response != null)
                        {
                            using (response)
                            {
                                try
                                {
                                    await clientSocket.SendAsync(response.Memory.Slice(0, responseLength), cancellationToken).ConfigureAwait(false);
                                }
                                catch (Exception ex)
                                {
                                    logger.LogDebug(ex, $"Send response to {clientSocket.RemoteEndPoint} failed");
                                }
                            }
                        }
                        else
                        {
                            logger.LogDebug($"Bad request from {clientSocket.RemoteEndPoint}");
                        }
                    }
                    finally
                    {
                        clientSocket.Dispose();
                    }
                });
            }
        }

        private async Task<bool> CreateTLS(IPAddress primaryAddress, IPAddress secondaryAddress, int primaryPort, int secondaryPort, IPAddress localPrimaryAddress, IPAddress localSecondaryAddress, int localPrimaryPort, int localSecondaryPort,
            X509Certificate2 certificate, ILogger logger, CancellationToken cancellationToken)
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
            Task[] tasks =
            [
                ListenTLS(a1p1Socket, a1p2Socket, a2p1Socket, a2p2Socket, primaryAddress, primaryPort, secondaryAddress, secondaryPort, certificate, logger, cancellationToken),
                ListenTLS(a1p2Socket, a1p1Socket, a2p2Socket, a2p1Socket, primaryAddress, secondaryPort, secondaryAddress, primaryPort, certificate, logger, cancellationToken),
                ListenTLS(a2p1Socket, a2p2Socket, a1p1Socket, a1p2Socket, secondaryAddress, primaryPort, primaryAddress, secondaryPort, certificate, logger, cancellationToken),
                ListenTLS(a2p2Socket, a2p1Socket, a1p2Socket, a1p1Socket, secondaryAddress, secondaryPort, primaryAddress, primaryPort, certificate, logger, cancellationToken),
            ];
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return true;
        }

        private async Task ListenTLS(Socket thisAddressThisPortSocket, Socket thisAddressOtherPortSocket, Socket otherAddressThisPortSocket, Socket otherAddressOtherPortSocket,
            IPAddress thisAddress, int thisPort, IPAddress otherAddress, int otherPort,
            X509Certificate2 certificate, ILogger logger, CancellationToken cancellationToken)
        {
            thisAddressThisPortSocket.Listen();
            while (!cancellationToken.IsCancellationRequested)
            {
                var memory = MemoryPool<byte>.Shared.Rent(1240);
                var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                Socket clientSocket;
                try
                {
                    clientSocket = await thisAddressThisPortSocket.AcceptAsync(cancellationToken).ConfigureAwait(false);
                    logger.LogDebug($"Accept TCP request from {clientSocket.RemoteEndPoint}");
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                CancellationTokenSource timeoutTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var networkStream = new NetworkStream(clientSocket, false);
                var sslStream = new SslStream(networkStream, true);
                _ = Task.Delay(5000).ContinueWith(task => timeoutTokenSource.Cancel());
                try
                {
                    await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate
                    }, timeoutTokenSource.Token);
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "Client handshake failed.");
                    clientSocket.Dispose();
                    continue;
                }
                int receivedBytes;
                try
                {
                    receivedBytes = await sslStream.ReadAsync(memory.Memory, timeoutTokenSource.Token).ConfigureAwait(false);
                }
                catch
                {
                    clientSocket.Dispose();
                    continue;
                }
                if (receivedBytes < 20)
                {
                    try
                    {
                        await clientSocket.DisconnectAsync(false, cancellationToken).ConfigureAwait(false);
                        clientSocket.Dispose();
                    }
                    catch
                    {

                    }
                    continue;
                }
                _ = Task.Run(async () =>
                {
                    IPEndPoint endPoint = (IPEndPoint)clientSocket.RemoteEndPoint!;
                    IMemoryOwner<byte>? response;
                    bool changeAddress, changePort;
                    int responseLength;
                    using (memory)
                    {
                        try
                        {
                            response = HandleRequest(memory.Memory.Span, receivedBytes, ref endPoint, thisAddress, thisPort, otherAddress, otherPort, out changeAddress, out changePort, out responseLength);
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "Handle request failed.");
                            return;
                        }
                    }
                    try
                    {
                        if (response != null)
                        {
                            using (response)
                            {
                                try
                                {
                                    await sslStream.WriteAsync(response.Memory.Slice(0, responseLength), cancellationToken).ConfigureAwait(false);
                                }
                                catch (Exception ex)
                                {
                                    logger.LogDebug(ex, $"Send response to {clientSocket.RemoteEndPoint} failed");
                                }
                            }
                        }
                        else
                        {
                            logger.LogDebug($"Bad request from {clientSocket.RemoteEndPoint}");
                        }
                    }
                    finally
                    {
                        sslStream.Dispose();
                        networkStream.Dispose();
                        clientSocket.Dispose();
                    }
                });
            }
        }

        private IMemoryOwner<byte>? HandleRequest(Span<byte> request, int length, ref IPEndPoint endPoint, IPAddress thisAddress, int thisPort,
            IPAddress otherAddress, int otherPort, out bool changeAddress, out bool changePort, out int responseLength)
        {
            changeAddress = false;
            changePort = false;
            responseLength = 0;
            ref MessageHeader header = ref MemoryMarshal.AsRef<MessageHeader>(request);
            if (header.MessageType != MessageType.Request)
                return null;
            bool isRFC5389 = header.MagicCookie == 0x42A41221;
            if (header.MessageLength + 20 != length)
                return null;
            var current = 20;
            var transactionId = request.Slice(8, 12);
            List<ushort> unknownAttributes = new List<ushort>();
            IPEndPoint? replyEndPoint = null;
            bool hasMessageIntegrity = false;
            bool messageIntegrityFailed = false;
            while (current < length)
            {
                if (length - current < 4)
                    return null;
                ref MessageAttributeType attributeType = ref MemoryMarshal.AsRef<MessageAttributeType>(request.Slice(current, 2));
                //rfc3489 11.2
                Span<byte> data;
                var attributeLength = BinaryPrimitives.ReadUInt16BigEndian(request.Slice(current + 2));
                if (length - current - 4 < attributeLength)
                    return null;
                data = request.Slice(current + 4, attributeLength);
                current += 4 + attributeLength;
                if (!attributeType.IsValid() && BinaryPrimitives.ReverseEndianness((ushort)attributeType) <= 0x7FFFu)
                {
                    unknownAttributes.Add((ushort)attributeType);
                    continue;
                }
                switch (attributeType)
                {
                    case MessageAttributeType.MappedAddress:
                    case MessageAttributeType.SourceAddress:
                    case MessageAttributeType.ChangedAddress:
                    case MessageAttributeType.UserName:
                    case MessageAttributeType.Password:
                    case MessageAttributeType.ErrorCode:
                    case MessageAttributeType.Unknown:
                    case MessageAttributeType.ReflectedFrom:
                        unknownAttributes.Add((ushort)attributeType);
                        break;
                    case MessageAttributeType.ResponseAddress:
                        if (data.Length < 4)
                            return null;
                        switch (data[1])
                        {
                            case 1:
                                if (data.Length < 8)
                                    return null;
                                replyEndPoint = new IPEndPoint(new IPAddress(data.Slice(4, 4)), MemoryMarshal.Read<ushort>(data.Slice(2, 2)));
                                break;
                            case 2:
                                if (data.Length < 20)
                                    return null;
                                replyEndPoint = new IPEndPoint(new IPAddress(data.Slice(4, 16)), MemoryMarshal.Read<ushort>(data.Slice(2, 2)));
                                break;
                            default:
                                return null;
                        }
                        break;
                    case MessageAttributeType.ChangeRequest:
                        if (data.Length != 4)
                            return null;
                        if ((data[3] & (byte)2) == (byte)2)
                            changePort = true;
                        if ((data[3] & (byte)4) == (byte)4)
                            changeAddress = true;
                        break;
                    case MessageAttributeType.MessageIntegrity:
                        if (current != length)
                            return null;
                        if (!request.ValidateMessageIntegrity())
                            return null;
                        hasMessageIntegrity = true;
                        messageIntegrityFailed = true;
                        break;
                }
            }
            responseLength = 20;
            bool hasError = false;
            List<Func<Span<byte>, Span<byte>, int>> responseAttributes = new List<Func<Span<byte>, Span<byte>, int>>();
            if (messageIntegrityFailed)
            {
                hasError = true;
                responseAttributes.Add(CreateErrorResponseAttribute(431, "The Binding Request contained a MESSAGE-INTEGRITY attribute, but the HMAC failed verification. This could be a sign of a potential attack, or client implementation error.", ref responseLength));
            }
            //else
            //{
            //    if (!hasMessageIntegrity)
            //    {
            //        hasError = true;
            //        responseAttributes.Add(CreateErrorResponseAttribute(401, "The Binding Request did not contain a MESSAGE-INTEGRITY attribute.", ref responseLength));
            //    }
            //}
            if (unknownAttributes.Count != 0)
            {
                hasError = true;
                responseAttributes.Add(CreateErrorResponseAttribute(420, "The server did not understand a mandatory attribute in the request.", ref responseLength));
                responseAttributes.Add(CreateUnknownAttributesAttribute(unknownAttributes, ref responseLength));
            }
            if (!hasError)
            {
                responseAttributes.Add(CreateMappedAddressAttribute(endPoint.Address, endPoint.Port, ref responseLength));
                responseAttributes.Add(CreateSourceAddressAttribute(thisAddress, thisPort, ref responseLength));
                responseAttributes.Add(CreateChangedAddressAttribute(otherAddress, otherPort, ref responseLength));
                if (isRFC5389)
                    responseAttributes.Add(CreateXORMappedAddressAttribute(endPoint.Address, endPoint.Port, ref responseLength));
                //if (replyEndPoint != null)
                //    responseAttributes.Add(CreateReflectedFromAttribute(endPoint.Address, endPoint.Port, ref responseLength));
            }
            if (!hasError && hasMessageIntegrity)
                responseLength += 28;
            var response = MemoryPool<byte>.Shared.Rent(responseLength);
            header = ref MemoryMarshal.AsRef<MessageHeader>(response.Memory.Span);
            header.MessageType = hasError ? MessageType.Error : MessageType.Response;
            BinaryPrimitives.WriteUInt16BigEndian(response.Memory.Span.Slice(2), (ushort)(responseLength - 20));
            if (isRFC5389)
                header.MagicCookie = 0x42A41221u;
            transactionId.CopyTo(response.Memory.Span.Slice(8, 12));
            var responseData = response.Memory.Span.Slice(20);
            foreach (var attribute in responseAttributes)
            {
                responseData = responseData.Slice(attribute(responseData, transactionId));
            }
            if (!hasError && hasMessageIntegrity)
                response.Memory.Span.SetMessageIntegrity();
            return response;
        }

        //rfc3489 11.2.9
        private Func<Span<byte>, Span<byte>, int> CreateErrorResponseAttribute(ushort code, string message, ref int length)
        {
            var messageLength = Encoding.UTF8.GetByteCount(message);
            if (messageLength > ushort.MaxValue - 4)
                throw new InvalidOperationException("Message data must less than or equal to 65531.");
            var attributeLength = 8 + Encoding.UTF8.GetByteCount(message);
            length += attributeLength;
            return new Func<Span<byte>, Span<byte>, int>((data, transactionId) =>
            {
                MemoryMarshal.Write(data, MessageAttributeType.ErrorCode);
                BinaryPrimitives.WriteUInt16BigEndian(data.Slice(2), (ushort)(messageLength + 4));
                //error code
                data[6] = (byte)(code / 100);
                data[7] = (byte)(code % 100);
                Encoding.UTF8.GetBytes(message, data.Slice(8, messageLength));
                return attributeLength;
            });
        }

        //rfc3489 11.2.10
        private Func<Span<byte>, Span<byte>, int> CreateUnknownAttributesAttribute(List<ushort> unknownAttributes, ref int length)
        {
            var attributeLength = unknownAttributes.Count / 4 * 12;
            length += attributeLength;
            return new Func<Span<byte>, Span<byte>, int>((data, transactionId) =>
            {
                for (int i = 0; i < unknownAttributes.Count; i += 4)
                {
                    MemoryMarshal.Write(data, MessageAttributeType.Unknown);
                    BinaryPrimitives.WriteUInt16BigEndian(data.Slice(2), 8);
                    BinaryPrimitives.WriteUInt16BigEndian(data.Slice(4), unknownAttributes[i]);
                    for (int j = 1; j < 3; j++)
                    {
                        if (i + j < unknownAttributes.Count)
                            BinaryPrimitives.WriteUInt16BigEndian(data.Slice((i + j) * 4), unknownAttributes[i + j]);
                        else
                            BinaryPrimitives.WriteUInt16BigEndian(data.Slice((i + j) * 4), unknownAttributes[i]);
                    }
                }
                return attributeLength;
            });
        }

        private Func<Span<byte>, Span<byte>, int> CreateMappedAddressAttribute(IPAddress address, int port, ref int length)
        {
            return CreateAddressAttribute(MessageAttributeType.MappedAddress, address, port, ref length);
        }

        private Func<Span<byte>, Span<byte>, int> CreateSourceAddressAttribute(IPAddress address, int port, ref int length)
        {
            return CreateAddressAttribute(MessageAttributeType.SourceAddress, address, port, ref length);
        }

        private Func<Span<byte>, Span<byte>, int> CreateChangedAddressAttribute(IPAddress address, int port, ref int length)
        {
            return CreateAddressAttribute(MessageAttributeType.ChangedAddress, address, port, ref length);
        }

        private Func<Span<byte>, Span<byte>, int> CreateReflectedFromAttribute(IPAddress address, int port, ref int length)
        {
            return CreateAddressAttribute(MessageAttributeType.ReflectedFrom, address, port, ref length);
        }
        private Func<Span<byte>, Span<byte>, int> CreateXORMappedAddressAttribute(IPAddress address, int port, ref int length)
        {
            int attributeLength;
            if (address.AddressFamily == AddressFamily.InterNetwork)
                attributeLength = 12;
            else
                attributeLength = 24;
            length += attributeLength;
            return new Func<Span<byte>, Span<byte>, int>((data, transactionId) =>
            {
                MemoryMarshal.Write(data, MessageAttributeType.XORMappedAddress);
                BinaryPrimitives.WriteUInt16BigEndian(data.Slice(2), (ushort)(attributeLength - 4));
                BinaryPrimitives.WriteUInt16BigEndian(data.Slice(6), (ushort)(((ushort)port) ^ 0x2112u));
                if (address.AddressFamily == AddressFamily.InterNetwork)
                    data[5] = 1;
                else
                    data[5] = 2;
                address.TryWriteBytes(data.Slice(8), out _);
                //0x42A41221
                data[8] ^= 0x21;
                data[9] ^= 0x12;
                data[10] ^= 0xA4;
                data[11] ^= 0x42;
                if (address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    for (int i = 0; i < 12; i++)
                    {
                        data[12 + i] ^= transactionId[i];
                    }
                }
                return attributeLength;
            });
        }

        private Func<Span<byte>, Span<byte>, int> CreateAddressAttribute(MessageAttributeType attributeType, IPAddress address, int port, ref int length)
        {
            int attributeLength;
            if (address.AddressFamily == AddressFamily.InterNetwork)
                attributeLength = 12;
            else
                attributeLength = 24;
            length += attributeLength;
            return new Func<Span<byte>, Span<byte>, int>((data, transactionId) =>
            {
                MemoryMarshal.Write(data, attributeType);
                BinaryPrimitives.WriteUInt16BigEndian(data.Slice(2), (ushort)(attributeLength - 4));
                BinaryPrimitives.WriteUInt16BigEndian(data.Slice(6), (ushort)port);
                if (address.AddressFamily == AddressFamily.InterNetwork)
                    data[5] = 1;
                else
                    data[5] = 2;
                address.TryWriteBytes(data.Slice(8), out _);
                return attributeLength;
            });
        }
    }
}
