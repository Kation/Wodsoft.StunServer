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
        private const int MinPayloadLength = 20;

        private readonly StunUdpProxyOptions _options;
        private readonly SocketAddress _proxyAddress;
        private readonly ILogger _logger;

        public StunUdpProxy(StunUdpProxyOptions options, ILogger logger)
        {
            _options = options;
            _logger = logger;
            var proxyAddress = options.ProxyEndPoint.Serialize();
            _proxyAddress = proxyAddress;
            var addressLength = GetAddressLength(options.PrimaryPortSocket.AddressFamily);
            PrimaryPortSocket = new StunUdpProxySocket(options.ProxySocket, proxyAddress, addressLength, 1);
            SecondaryPortSocket = new StunUdpProxySocket(options.ProxySocket, proxyAddress, addressLength, 2);
        }

        public async Task RunAsync(CancellationToken cancellationToken = default)
        {
            var proxyAddress = _proxyAddress;
            var buffer = new byte[1500];
            int length;
            var primarySocket = _options.PrimaryPortSocket;
            var secondarySocket = _options.SecondaryPortSocket;
            var remoteAddress = new SocketAddress(proxyAddress.Family);
            var addressLength = GetAddressLength(remoteAddress.Family);
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
                if (!TryUnwrap(buffer.AsSpan(0, length), remoteAddress.Family, out var payloadLength, out var secondary))
                {
                    _logger.LogWarning($"Receive from proxy but the packet is invalid, length is {length}.");
                    continue;
                }
                var socket = secondary ? secondarySocket : primarySocket;
                buffer.AsSpan(payloadLength, addressLength).CopyTo(remoteAddress.Buffer.Span.Slice(2));
                _logger.LogDebug($"Send UDP proxy response to {remoteAddress}");
                await socket.SendToAsync(buffer.AsMemory(0, payloadLength), SocketFlags.None, remoteAddress, cancellationToken);
            }
        }

        public IStunUdpSocket PrimaryPortSocket { get; }

        public IStunUdpSocket SecondaryPortSocket { get; }

        /// <summary>
        /// 尾部由 <paramref name="family"/> 对应的 SocketAddress 片段（端口 + 地址）和 1 个字节的标志位组成。
        /// </summary>
        internal static int GetAddressLength(AddressFamily family) => family == AddressFamily.InterNetwork ? 6 : 18;

        /// <summary>
        /// 去掉 <see cref="StunUdpProxySocket.SendToAsync"/> 追加在报文尾部的端口地址片段和标志位，
        /// 得到真实的 STUN 数据长度。
        /// </summary>
        internal static bool TryUnwrap(ReadOnlySpan<byte> packet, AddressFamily family, out int payloadLength, out bool secondary)
        {
            payloadLength = 0;
            secondary = false;
            if (packet.Length == 0)
                return false;
            var flag = packet[^1];
            if ((flag & 1) == 1)
                secondary = false;
            else if ((flag & 2) == 2)
                secondary = true;
            else
                return false;
            payloadLength = packet.Length - GetAddressLength(family) - 1;
            return payloadLength >= MinPayloadLength;
        }

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
