using System.Buffers.Binary;
using System.Net.Sockets;

namespace Wodsoft.StunServer.UnitTest;

public class StunUdpProxyTests
{
    // MAPPED-ADDRESS / XOR-MAPPED-ADDRESS / RESPONSE-ORIGIN / OTHER-ADDRESS 各 12 字节
    private const int Rfc5389ResponseLength = 20 + 4 * 12;

    private static readonly byte[] OtherAddress = [0x80, 0x2C, 0x00, 0x08, 0x00, 0x01, 0x0D, 0x97, 0xC6, 0x33, 0x64, 0x14];

    [Theory]
    [InlineData(AddressFamily.InterNetwork, 6, 1, false)]
    [InlineData(AddressFamily.InterNetwork, 6, 2, true)]
    [InlineData(AddressFamily.InterNetworkV6, 18, 1, false)]
    [InlineData(AddressFamily.InterNetworkV6, 18, 2, true)]
    public void Unwrap_strips_the_address_fragment_and_the_flag(AddressFamily family, int addressLength, byte flag, bool secondary)
    {
        var payload = new byte[Rfc5389ResponseLength];
        var packet = new byte[payload.Length + addressLength + 1];
        payload.CopyTo(packet, 0);
        packet[^1] = flag;

        Assert.True(StunUdpProxy.TryUnwrap(packet, family, out var payloadLength, out var actualSecondary));

        Assert.Equal(payload.Length, payloadLength);
        Assert.Equal(secondary, actualSecondary);
    }

    [Theory]
    [InlineData(AddressFamily.InterNetwork, 6)]
    [InlineData(AddressFamily.InterNetworkV6, 18)]
    public void Other_address_attribute_is_not_truncated(AddressFamily family, int addressLength)
    {
        var payload = new byte[Rfc5389ResponseLength];
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(2), (ushort)(Rfc5389ResponseLength - 20));
        OtherAddress.CopyTo(payload, Rfc5389ResponseLength - OtherAddress.Length);

        var packet = new byte[payload.Length + addressLength + 1];
        payload.CopyTo(packet, 0);
        packet[^1] = 1;

        Assert.True(StunUdpProxy.TryUnwrap(packet, family, out var payloadLength, out _));
        Assert.Equal(Rfc5389ResponseLength, payloadLength);
        Assert.Equal(OtherAddress, packet.AsSpan(payloadLength - OtherAddress.Length, OtherAddress.Length).ToArray());
    }

    [Fact]
    public void Empty_packet_is_rejected()
    {
        Assert.False(StunUdpProxy.TryUnwrap([], AddressFamily.InterNetwork, out var payloadLength, out _));
        Assert.Equal(0, payloadLength);
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x04)]
    [InlineData(0x08)]
    [InlineData(0x40)]
    [InlineData(0x80)]
    public void Packet_without_a_known_flag_is_rejected(byte flag)
    {
        var packet = new byte[Rfc5389ResponseLength + 7];
        packet[^1] = flag;

        Assert.False(StunUdpProxy.TryUnwrap(packet, AddressFamily.InterNetwork, out _, out _));
    }

    [Theory]
    [InlineData(AddressFamily.InterNetwork, 26)]
    [InlineData(AddressFamily.InterNetwork, 12)]
    [InlineData(AddressFamily.InterNetworkV6, 38)]
    public void Packet_shorter_than_the_trailer_plus_a_stun_header_is_rejected(AddressFamily family, int packetLength)
    {
        var packet = new byte[packetLength];
        packet[^1] = 1;

        Assert.False(StunUdpProxy.TryUnwrap(packet, family, out _, out _));
    }

    [Fact]
    public void Address_length_matches_the_socket_address_fragment()
    {
        Assert.Equal(6, StunUdpProxy.GetAddressLength(AddressFamily.InterNetwork));
        Assert.Equal(18, StunUdpProxy.GetAddressLength(AddressFamily.InterNetworkV6));
    }
}
