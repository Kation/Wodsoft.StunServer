using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Wodsoft.StunServer
{
    public class StunUdpSocket : IStunUdpSocket, IDisposable
    {
        private readonly Socket _socket;

        public StunUdpSocket(Socket socket)
        {
            _socket = socket;
        }

        public AddressFamily AddressFamily => _socket.AddressFamily;

        public IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint!;

        public ValueTask<int> ReceiveFromAsync(Memory<byte> buffer, SocketFlags socketFlags, SocketAddress receivedAddress, CancellationToken cancellationToken = default)
        {
            return _socket.ReceiveFromAsync(buffer, socketFlags, receivedAddress, cancellationToken);
        }

        public ValueTask<int> SendToAsync(ReadOnlyMemory<byte> buffer, SocketFlags socketFlags, SocketAddress socketAddress, CancellationToken cancellationToken = default)
        {
            return _socket.SendToAsync(buffer, socketFlags, socketAddress, cancellationToken);
        }

        public void Dispose()
        {
            _socket.Dispose();
        }
    }
}
