using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Wodsoft.StunServer
{
    public class StunUdpProxy
    {
        private readonly StunUdpProxyOptions _options;
        private readonly SocketAddress _proxyAddress;
        private readonly ILogger _logger;

        public StunUdpProxy(StunUdpProxyOptions options, ILogger logger)
        {
            _options = options;
            _logger = logger;
            var proxyAddress = options.ProxyEndPoint.Serialize();
            _proxyAddress = proxyAddress;
            PrimaryPortSocket = new StunUdpProxySocket(options.ProxySocket, proxyAddress, options.PrimaryPortSocket.AddressFamily == AddressFamily.InterNetwork ? 6 : 18, 1);
            SecondaryPortSocket = new StunUdpProxySocket(options.ProxySocket, proxyAddress, options.PrimaryPortSocket.AddressFamily == AddressFamily.InterNetwork ? 6 : 18, 2);
        }

        public async Task RunAsync(CancellationToken cancellationToken = default)
        {
            var proxyAddress = _proxyAddress;
            var buffer = new byte[1500];
            int length;
            var primarySocket = _options.PrimaryPortSocket;
            var secondarySocket = _options.SecondaryPortSocket;
            Socket socket;
            var remoteAddress = new SocketAddress(proxyAddress.Family);
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    length = await _options.ProxySocket.ReceiveFromAsync(buffer, SocketFlags.None, proxyAddress, cancellationToken);
                }
                catch (SocketException)
                {
                    continue;
                }
                catch (TaskCanceledException)
                {
                    return;
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                var flag = buffer[length - 1];
                if ((flag & 1) == 1)
                {
                    socket = primarySocket;
                }
                else if ((flag & 2) == 2)
                {
                    socket = secondarySocket;
                }
                else
                {
                    _logger.LogWarning($"Receive from proxy but flag is {flag}.");
                    continue;
                }
                if (remoteAddress.Family == AddressFamily.InterNetwork)
                {
                    buffer.AsSpan(length - 7, 6).CopyTo(remoteAddress.Buffer.Span.Slice(2));
                }
                else
                {
                    buffer.AsSpan(length - 19, 18).CopyTo(remoteAddress.Buffer.Span.Slice(2));
                }
                _logger.LogDebug($"Send UDP proxy response to {remoteAddress}");
                await primarySocket.SendToAsync(buffer.AsMemory(0, length - 19), SocketFlags.None, remoteAddress, cancellationToken);
            }
        }

        public IStunUdpSocket PrimaryPortSocket { get; }

        public IStunUdpSocket SecondaryPortSocket { get; }

        private class StunUdpProxySocket : IStunUdpSocket
        {
            private Socket _socket;
            private SocketAddress _proxyAddress;
            private int _addressLength;
            private byte _flag;

            public StunUdpProxySocket(Socket socket, SocketAddress proxyAddress, int addressLength, byte flag)
            {
                _socket = socket;
                _addressLength = addressLength;
                _flag = flag;
                _proxyAddress = proxyAddress;
            }

            public AddressFamily AddressFamily => _socket.AddressFamily;

            public IPEndPoint LocalEndPoint => throw new NotSupportedException();

            public ValueTask<int> ReceiveFromAsync(Memory<byte> buffer, SocketFlags socketFlags, SocketAddress receivedAddress, CancellationToken cancellationToken = default)
            {
                throw new NotSupportedException();
            }

            public ValueTask<int> SendToAsync(byte[] buffer, int length, SocketFlags socketFlags, SocketAddress socketAddress, CancellationToken cancellationToken = default)
            {
                socketAddress.Buffer.Span.Slice(2, _addressLength).CopyTo(buffer.AsSpan(length));
                buffer[length + _addressLength] = _flag;
                return _socket.SendToAsync(buffer.AsMemory(0, length + _addressLength + 1), SocketFlags.None, _proxyAddress, cancellationToken);
            }
        }
    }
}
