using System.Net;
using System.Net.Sockets;

namespace Wodsoft.StunServer.UnitTest;

public class SocketAddressFormatTests
{
    private static SocketAddress Create(IPAddress address, int port) => new IPEndPoint(address, port).Serialize();

    [Theory]
    [InlineData("192.168.1.10", 5060, "192.168.1.10:5060")]
    [InlineData("0.0.0.0", 0, "0.0.0.0:0")]
    [InlineData("127.0.0.1", 65535, "127.0.0.1:65535")]
    [InlineData("255.255.255.255", 65535, "255.255.255.255:65535")]
    [InlineData("::", 3478, "[::]:3478")]
    [InlineData("::1", 3478, "[::1]:3478")]
    [InlineData("2001:db8::1", 3478, "[2001:db8::1]:3478")]
    [InlineData("1:2:3:4:5:6:7:8", 1, "[1:2:3:4:5:6:7:8]:1")]
    [InlineData("0:0:1:0:0:0:0:1", 1, "[0:0:1::1]:1")]
    [InlineData("100::", 1, "[100::]:1")]
    [InlineData("fe80::1%7", 9000, "[fe80::1%7]:9000")]
    [InlineData("::1%3", 1, "[::1]:1")]
    [InlineData("::ffff:192.168.1.1", 80, "[::ffff:192.168.1.1]:80")]
    [InlineData("::192.168.1.1", 80, "[::192.168.1.1]:80")]
    [InlineData("fe80::5efe:1.2.3.4", 80, "[fe80::5efe:1.2.3.4]:80")]
    public void Format_matches_expected(string address, int port, string expected)
    {
        var socketAddress = Create(IPAddress.Parse(address), port);

        Assert.Equal(expected, socketAddress.Format());
        // 与内置转换结果保持一致（含 scope id 规则）。
        Assert.Equal(((IPEndPoint)new IPEndPoint(IPAddress.Any, 0).Create(socketAddress)).ToString(), socketAddress.Format());
    }

    [Fact]
    public void Format_matches_runtime_conversion_for_random_ipv4()
    {
        var random = new Random(0x5A17);
        var template = new IPEndPoint(IPAddress.Any, 0);
        int mismatches = 0;

        for (int i = 0; i < 20000; i++)
        {
            byte[] bytes = new byte[4];
            random.NextBytes(bytes);
            int port = random.Next(0, 65536);
            var socketAddress = new IPEndPoint(new IPAddress(bytes), port).Serialize();
            string expected = ((IPEndPoint)template.Create(socketAddress)).ToString();
            if (expected != socketAddress.Format())
                mismatches++;
        }

        Assert.Equal(0, mismatches);
    }

    [Fact]
    public void Format_matches_runtime_conversion_for_random_ipv6()
    {
        var random = new Random(0xBEEF);
        var template = new IPEndPoint(IPAddress.Any, 0);
        int mismatches = 0;
        string? firstMismatch = null;

        for (int i = 0; i < 20000; i++)
        {
            byte[] bytes = new byte[16];
            random.NextBytes(bytes);
            long scopeId = random.Next(0, 4) == 0 ? random.Next(1, 1000) : 0;
            int port = random.Next(0, 65536);
            var socketAddress = new IPEndPoint(new IPAddress(bytes, scopeId), port).Serialize();
            string expected = ((IPEndPoint)template.Create(socketAddress)).ToString();
            string actual = socketAddress.Format();
            if (expected != actual)
            {
                mismatches++;
                firstMismatch ??= $"{expected} != {actual}";
            }
        }

        Assert.True(mismatches == 0, $"mismatches: {mismatches}, first: {firstMismatch}");
    }

    [Fact]
    public void TryFormat_requires_the_maximum_length()
    {
        var ipv4 = Create(IPAddress.Parse("1.2.3.4"), 5);
        var ipv6 = Create(IPAddress.Parse("2001:db8::1"), 5);

        Span<char> buffer = stackalloc char[64];

        Assert.True(ipv4.TryFormat(buffer.Slice(0, 21), out int written));
        Assert.Equal("1.2.3.4:5", new string(buffer.Slice(0, written)));
        Assert.False(ipv4.TryFormat(buffer.Slice(0, 20), out _));

        Assert.True(ipv6.TryFormat(buffer.Slice(0, 58), out written));
        Assert.Equal("[2001:db8::1]:5", new string(buffer.Slice(0, written)));
        Assert.False(ipv6.TryFormat(buffer.Slice(0, 57), out _));
    }

    [Fact]
    public void Format_only_allocates_the_result_string()
    {
        var socketAddress = Create(IPAddress.Parse("2001:db8::1"), 3478);
        _ = socketAddress.Format();

        long before = GC.GetAllocatedBytesForCurrentThread();
        string text = socketAddress.Format();
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal("[2001:db8::1]:3478", text);
        Assert.InRange(allocated, 0, text.Length * 2 + 32);
    }

    [Fact]
    public void Format_rejects_unparsable_socket_address_with_fallback()
    {
        var unix = new SocketAddress(AddressFamily.Unix, 110);

        Assert.False(unix.TryFormat(new char[64], out int written));
        Assert.Equal(0, written);
        Assert.Equal(unix.ToString(), unix.Format());
    }

    [Theory]
    [InlineData(AddressFamily.InterNetwork)]
    [InlineData(AddressFamily.InterNetworkV6)]
    public void Format_works_for_address_received_from_udp_socket(AddressFamily family)
    {
        if (family == AddressFamily.InterNetworkV6 && !Socket.OSSupportsIPv6)
            return;

        IPAddress loopback = family == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback;
        using var server = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        server.Bind(new IPEndPoint(loopback, 0));
        using var client = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        client.Bind(new IPEndPoint(loopback, 0));

        client.SendTo([1, 2, 3, 4], server.LocalEndPoint!);

        var received = new SocketAddress(family);
        int length = server.ReceiveFrom(new byte[16], SocketFlags.None, received);

        Assert.Equal(4, length);
        Assert.Equal(client.LocalEndPoint!.ToString(), received.Format());
    }

    [Theory]
    [InlineData("192.168.1.10")]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("2001:db8::1")]
    [InlineData("1:2:3:4:5:6:7:8")]
    [InlineData("0:0:1:0:0:0:0:1")]
    [InlineData("fe80::1")]
    [InlineData("::ffff:192.168.1.1")]
    [InlineData("::192.168.1.1")]
    [InlineData("fe80::5efe:1.2.3.4")]
    public void Format_address_matches_IPAddress(string address)
    {
        var ip = IPAddress.Parse(address);
        byte[] bytes = ip.GetAddressBytes();

        Assert.Equal(ip.ToString(), MessageExtensions.Format(bytes));
        Assert.Equal(ip.ToString(), MessageExtensions.Format(bytes.AsSpan()));
    }

    [Fact]
    public void Format_address_matches_runtime_for_random_bytes()
    {
        var random = new Random(0x2024);
        int mismatches = 0;

        for (int i = 0; i < 10000; i++)
        {
            byte[] v4 = new byte[4];
            random.NextBytes(v4);
            if (new IPAddress(v4).ToString() != MessageExtensions.Format(v4))
                mismatches++;

            byte[] v6 = new byte[16];
            random.NextBytes(v6);
            if (new IPAddress(v6).ToString() != MessageExtensions.Format(v6))
                mismatches++;
        }

        Assert.Equal(0, mismatches);
    }

    [Fact]
    public void Format_address_handles_stun_attribute_bytes()
    {
        Assert.Equal("203.0.113.5", MessageExtensions.Format([203, 0, 113, 5]));
        Assert.Equal("2001:db8::1", MessageExtensions.Format([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    }

    [Fact]
    public void Format_address_rejects_invalid_input()
    {
        Assert.Throws<ArgumentNullException>(() => MessageExtensions.Format((byte[])null!));

        foreach (int length in new[] { 0, 3, 5, 15, 17 })
            Assert.Throws<ArgumentException>(() => MessageExtensions.Format(new byte[length]));
    }

    [Fact]
    public void Format_address_only_allocates_the_result_string()
    {
        byte[] address = IPAddress.Parse("2001:db8::dead:beef").GetAddressBytes();
        _ = MessageExtensions.Format(address);

        long before = GC.GetAllocatedBytesForCurrentThread();
        string text = MessageExtensions.Format(address);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal("2001:db8::dead:beef", text);
        Assert.InRange(allocated, 0, text.Length * 2 + 32);
    }

    [Fact]
    public void Format_into_span_is_zero_allocation()
    {
        var v4 = Create(IPAddress.Parse("192.168.1.10"), 5060);
        var v6 = Create(IPAddress.Parse("fe80::1%7"), 9000);
        Span<char> buffer = stackalloc char[58];

        int written = v4.Format(buffer);
        Assert.Equal("192.168.1.10:5060", buffer[..written].ToString());
        written = v6.Format(buffer);
        Assert.Equal("[fe80::1%7]:9000", buffer[..written].ToString());

        v4.Format(buffer);

        long before = GC.GetAllocatedBytesForCurrentThread();
        int measured = v4.Format(buffer);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(17, measured);
        Assert.Equal(0, allocated);
    }

    [Fact]
    public void Format_into_span_requires_maximum_length()
    {
        var v4 = Create(IPAddress.Parse("1.2.3.4"), 5);
        var v6 = Create(IPAddress.Parse("2001:db8::1"), 5);
        Span<char> buffer = stackalloc char[64];

        int written = v4.Format(buffer[..21]);
        Assert.Equal("1.2.3.4:5", buffer[..written].ToString());
        written = v6.Format(buffer[..58]);
        Assert.Equal("[2001:db8::1]:5", buffer[..written].ToString());

        Assert.True(ThrowsEndpoint(buffer[..20], v4));
        Assert.True(ThrowsEndpoint(buffer[..57], v6));
    }

    [Fact]
    public void Format_address_into_span_is_zero_allocation()
    {
        byte[] v4 = [192, 168, 1, 10];
        byte[] v6 = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        Span<char> buffer = stackalloc char[39];

        int written = MessageExtensions.Format(v4, buffer);
        Assert.Equal("192.168.1.10", buffer[..written].ToString());
        written = MessageExtensions.Format(v6, buffer);
        Assert.Equal("2001:db8::1", buffer[..written].ToString());

        MessageExtensions.Format(v4, buffer);

        long before = GC.GetAllocatedBytesForCurrentThread();
        int measured = MessageExtensions.Format(v4, buffer);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(12, measured);
        Assert.Equal(0, allocated);
    }

    [Fact]
    public void Format_address_into_span_validates_length_and_space()
    {
        Span<char> buffer = stackalloc char[39];

        Assert.Equal(15, MessageExtensions.Format([255, 255, 255, 255], buffer[..15]));
        Assert.True(ThrowsAddress(buffer[..14], [1, 2, 3, 4]));
        Assert.True(ThrowsAddress(buffer, [1, 2, 3]));
    }

    [Fact]
    public void Format_into_span_matches_string_overload_for_random_addresses()
    {
        var random = new Random(0x9E37);
        Span<char> endpointBuffer = stackalloc char[58];
        Span<char> addressBuffer = stackalloc char[39];
        int mismatches = 0;

        for (int i = 0; i < 5000; i++)
        {
            byte[] bytes = new byte[random.Next(2) == 0 ? 4 : 16];
            random.NextBytes(bytes);
            int port = random.Next(0, 65536);
            var socketAddress = new IPEndPoint(new IPAddress(bytes), port).Serialize();

            int endpointLength = socketAddress.Format(endpointBuffer);
            if (!endpointBuffer[..endpointLength].SequenceEqual(socketAddress.Format()))
                mismatches++;

            int addressLength = MessageExtensions.Format(bytes, addressBuffer);
            if (!addressBuffer[..addressLength].SequenceEqual(MessageExtensions.Format(bytes)))
                mismatches++;
        }

        Assert.Equal(0, mismatches);
    }

    private static bool ThrowsEndpoint(Span<char> destination, SocketAddress socketAddress)
    {
        try
        {
            socketAddress.Format(destination);
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static bool ThrowsAddress(Span<char> destination, byte[] address)
    {
        try
        {
            MessageExtensions.Format(address, destination);
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }
}
