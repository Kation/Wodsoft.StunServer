using Microsoft.Extensions.Logging;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Wodsoft.StunServer
{
    public class StunTcpService : StunServiceBase
    {
        private readonly StunTcpServiceOptions _options;
        private readonly ILogger _logger;

        public StunTcpService(StunTcpServiceOptions options, ILogger logger)
        {
            _options = options;
            _logger = logger;
        }

        public async Task RunAsync(CancellationToken cancellationToken = default)
        {
            var listenSocket = _options.Socket;
            listenSocket.Listen();
            while (!cancellationToken.IsCancellationRequested)
            {
                Socket clientSocket;
                try
                {
                    clientSocket = await listenSocket.AcceptAsync(cancellationToken).ConfigureAwait(false);
                    _logger.LogDebug($"Accept TCP request from {clientSocket.RemoteEndPoint}");
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                _ = ProcessConnection(clientSocket, cancellationToken);
            }
        }

        protected override bool IsValidAttribute(MessageAttributeType attributeType)
        {
            switch (attributeType)
            {
                case MessageAttributeType.ResponseAddress:
                case MessageAttributeType.ChangeRequest:
                case MessageAttributeType.ResponsePort:
                    return false;
                default:
                    return base.IsValidAttribute(attributeType);
            }
        }

        private async Task ProcessConnection(Socket clientSocket, CancellationToken cancellationToken)
        {
            var buffer = RentBuffer();
            var filled = 0;
            var thisAddress = _options.PrimaryAddress.GetAddressBytes();
            var otherAddress = _options.SecondaryAddress.GetAddressBytes();
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var headerReady = await EnsureFilledAsync(clientSocket, buffer, filled, 20, cancellationToken).ConfigureAwait(false);
                    if (headerReady < 0)
                        return;
                    filled = headerReady;

                    var messageLength = 20 + BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2, 2));
                    if (messageLength > buffer.Length)
                    {
                        _logger.LogDebug($"STUN message from {clientSocket.RemoteEndPoint} exceeds buffer.");
                        return;
                    }

                    var messageReady = await EnsureFilledAsync(clientSocket, buffer, filled, messageLength, cancellationToken).ConfigureAwait(false);
                    if (messageReady < 0)
                        return;
                    filled = messageReady;

                    var result = await ProcessMessage(clientSocket, buffer, messageLength, thisAddress, otherAddress).ConfigureAwait(false);
                    var remaining = filled - messageLength;
                    if (remaining > 0)
                        Buffer.BlockCopy(buffer, messageLength, buffer, 0, remaining);
                    filled = remaining;

                    if (result.Response == null)
                        continue;

                    try
                    {
                        _logger.LogDebug($"Send TCP response from {clientSocket.LocalEndPoint} to {clientSocket.RemoteEndPoint}");
                        await clientSocket.SendAsync(result.Response.AsMemory(0, result.ResponseLength), cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger.LogDebug(ex, $"Send response to {clientSocket.RemoteEndPoint} failed");
                        return;
                    }
                    finally
                    {
                        ReturnBuffer(result.Response);
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Handle TCP connection failed.");
            }
            finally
            {
                ReturnBuffer(buffer);
                clientSocket.Dispose();
            }
        }

        private async Task<int> EnsureFilledAsync(Socket clientSocket, byte[] buffer, int filled, int required, CancellationToken cancellationToken)
        {
            while (filled < required)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                int read;
                try
                {
                    read = await clientSocket.ReceiveAsync(buffer.AsMemory(filled, buffer.Length - filled), timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    _logger.LogDebug($"TCP connection from {clientSocket.RemoteEndPoint} idle timeout.");
                    return -1;
                }
                catch (OperationCanceledException)
                {
                    return -1;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, $"Receive TCP request from {clientSocket.RemoteEndPoint} failed.");
                    return -1;
                }
                if (read == 0)
                {
                    if (filled != 0)
                        _logger.LogDebug($"Incomplete STUN message from {clientSocket.RemoteEndPoint}.");
                    return -1;
                }
                filled += read;
            }
            return filled;
        }

        private async ValueTask<StunRequestResult> ProcessMessage(Socket clientSocket, byte[] buffer, int messageLength, byte[] thisAddress, byte[] otherAddress)
        {
            var endPoint = (IPEndPoint)clientSocket.RemoteEndPoint!;
            StunRequestResult result;
            try
            {
                result = await HandleRequestAsync(buffer.AsMemory(0, messageLength), endPoint.Address.GetAddressBytes(), (ushort)endPoint.Port, thisAddress, _options.PrimaryPort, otherAddress, _options.SecondaryPort).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Handle request failed.");
                return default;
            }
            if (result.Response == null)
                _logger.LogDebug($"Bad request from {clientSocket.RemoteEndPoint}");
            return result;
        }
    }
}
