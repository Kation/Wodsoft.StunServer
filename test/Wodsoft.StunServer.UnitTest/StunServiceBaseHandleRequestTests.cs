using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Wodsoft.StunServer.UnitTest;

public class StunServiceBaseHandleRequestTests
{
    private const ushort RemotePort = 54320;
    private const ushort LocalPort = 3478;
    private const ushort OtherPort = 3479;

    private static readonly byte[] TxId = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    private static readonly byte[] MagicCookie = [0x21, 0x12, 0xA4, 0x42];
    private static readonly byte[] RemoteV4 = [203, 0, 113, 5];
    private static readonly byte[] LocalV4 = [192, 0, 2, 10];
    private static readonly byte[] OtherV4 = [198, 51, 100, 20];
    private static readonly byte[] RemoteV6 = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    private static readonly byte[] LocalV6 = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    private static readonly byte[] OtherV6 = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
    private static readonly byte[] User = "user"u8.ToArray();
    private static readonly byte[] RealmName = "example.org"u8.ToArray();
    private static readonly byte[] PasswordBytes = "password"u8.ToArray();
    private const string BadRequest = "Bad Request";
    private const string Unauthorized = "Unauthorized";
    private const string StaleNonce = "Stale Nonce";
    private const string UnknownAttributeReason = "The server did not understand a mandatory attribute in the request.";

    [Theory]
    [InlineData(MessageType.Response)]
    [InlineData(MessageType.Error)]
    public async Task Non_request_message_is_discarded(MessageType type)
    {
        var request = new RequestBuilder().Type(type).Add(MessageAttributeType.ChangeRequest, Change(0x06)).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Indication_is_discarded_before_attributes_are_parsed()
    {
        var request = new RequestBuilder().WireType(0x0011).Add(MessageAttributeType.ChangeRequest, Change(0x06)).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    public async Task Message_shorter_than_the_header_throws(int length)
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SendAsync(new FakeStunService(), new byte[length]));
    }

    [Theory]
    [InlineData(8)]
    [InlineData(19)]
    public async Task Request_shorter_than_20_bytes_is_discarded(int length)
    {
        var request = new byte[length];
        BinaryPrimitives.WriteUInt16LittleEndian(request, (ushort)MessageType.Request);
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Non_request_shorter_than_20_bytes_is_discarded()
    {
        var request = new byte[8];
        BinaryPrimitives.WriteUInt16LittleEndian(request, (ushort)MessageType.Error);
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Declared_length_shorter_than_the_buffer_is_discarded()
    {
        var request = new RequestBuilder().Length(0).Add(MessageAttributeType.ChangeRequest, Change(0x06)).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Buffer_longer_than_the_declared_message_is_discarded()
    {
        var message = new RequestBuilder().Build();
        var request = new byte[message.Length + 4];
        message.CopyTo(request);
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Little_endian_message_length_is_discarded()
    {
        var request = new RequestBuilder().Add(MessageAttributeType.ChangeRequest, Change(0x02)).Build();
        (request[2], request[3]) = (request[3], request[2]);
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Trailing_byte_count_below_an_attribute_header_is_discarded()
    {
        var request = new RequestBuilder().Trailing([0x00, 0x01]).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Attribute_value_that_exceeds_the_message_is_discarded()
    {
        var request = new byte[24];
        BinaryPrimitives.WriteUInt16LittleEndian(request, (ushort)MessageType.Request);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(2), 4);
        MagicCookie.CopyTo(request, 4);
        TxId.CopyTo(request, 8);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(22), 100);
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Attribute_padding_that_exceeds_the_message_is_discarded()
    {
        var request = new RequestBuilder().AddRaw(0x0006, [0x61]).Build();
        var truncated = request.AsSpan(0, request.Length - 3).ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(truncated.AsSpan(2), (ushort)(truncated.Length - 20));
        AssertDiscarded(await SendAsync(new FakeStunService(), truncated));
    }

    [Fact]
    public async Task Attribute_padding_is_excluded_from_the_value_and_keeps_the_next_attribute_aligned()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.UserName, "a"u8.ToArray())
            .AddRaw(0x8022, "stun!"u8.ToArray())
            .Add(MessageAttributeType.ChangeRequest, Change(0x02))
            .Build();

        var result = await SendAsync(new FakeStunService(), request);

        AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);
        AssertReply(result, null, 0, changeAddress: false, changePort: true);
    }

    [Theory]
    [InlineData(19)]
    [InlineData(21)]
    [InlineData(0)]
    public async Task Message_integrity_with_the_wrong_length_is_discarded(int length)
    {
        var request = new RequestBuilder().Add(MessageAttributeType.MessageIntegrity, new byte[length]).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(20)]
    public async Task Message_integrity_sha256_with_the_wrong_length_is_discarded(int length)
    {
        var request = new RequestBuilder().Add(MessageAttributeType.MessageIntegritySHA256, new byte[length]).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Duplicate_message_integrity_is_discarded()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.ChangeRequest, Change(0x06))
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Duplicate_message_integrity_sha256_is_discarded()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.ChangeRequest, Change(0x04))
            .Add(MessageAttributeType.MessageIntegritySHA256, new byte[32])
            .Add(MessageAttributeType.MessageIntegritySHA256, new byte[32])
            .Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Theory]
    [InlineData(MessageAttributeType.XORMappedAddress)]
    [InlineData(MessageAttributeType.ResponseOrigin)]
    [InlineData(MessageAttributeType.OtherAddress)]
    public async Task Known_attribute_without_a_request_handler_discards_the_message(MessageAttributeType type)
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.ChangeRequest, Change(0x06))
            .Add(type, [0, 0, 0, 0])
            .Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Theory]
    [InlineData(MessageAttributeType.MappedAddress)]
    [InlineData(MessageAttributeType.SourceAddress)]
    [InlineData(MessageAttributeType.ChangedAddress)]
    [InlineData(MessageAttributeType.Password)]
    [InlineData(MessageAttributeType.ErrorCode)]
    [InlineData(MessageAttributeType.Unknown)]
    [InlineData(MessageAttributeType.ReflectedFrom)]
    [InlineData(MessageAttributeType.Padding)]
    public async Task Disallowed_comprehension_required_attribute_returns_420(MessageAttributeType type)
    {
        var request = new RequestBuilder().Add(type, []).Build();
        var result = await SendAsync(new FakeStunService(), request);
        var attributes = AssertError(result, 420, UnknownAttributeReason, rfc5389: true);
        Assert.Single(attributes);
    }

    [Fact]
    public async Task Comprehension_required_boundary_is_unknown_and_optional_boundary_is_ignored()
    {
        var required = new RequestBuilder().AddRaw(0x7FFF, []).Build();
        var requiredResult = await SendAsync(new FakeStunService(), required);
        AssertError(requiredResult, 420, UnknownAttributeReason, rfc5389: true);

        var optional = new RequestBuilder().AddRaw(0x8000, []).Add(MessageAttributeType.ChangeRequest, Change(0x04)).Build();
        var optionalResult = await SendAsync(new FakeStunService(), optional);
        AssertSuccess(optionalResult, rfc5389: true, classicPrefixCleared: false);
        AssertReply(optionalResult, null, 0, changeAddress: true, changePort: false);
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 0)]
    [InlineData(4, 12)]
    [InlineData(5, 12)]
    [InlineData(8, 24)]
    public async Task Unknown_attributes_are_appended_in_groups_of_four(int count, int extra)
    {
        var builder = new RequestBuilder();
        for (var i = 0; i < count; i++)
            builder.AddRaw((ushort)(0x0060 + i), [(byte)i]);
        var result = await SendAsync(new FakeStunService(), builder.Build());

        var attributes = AssertError(result, 420, UnknownAttributeReason, rfc5389: true);
        var errorSize = 4 + Pad(attributes[0].Value.Length);
        Assert.Equal(20 + errorSize + extra, result.ResponseLength);
        if (count < 4)
            Assert.Single(attributes);
        else
            Assert.Equal(0x000A, attributes[1].Type);
    }

    [Fact]
    public async Task Unknown_required_attribute_does_not_stop_later_attributes_from_updating_the_result()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.ChangeRequest, Change(0x06))
            .AddRaw(0x000D, [0xFF])
            .Add(MessageAttributeType.ResponsePort, PortValue(4000, 0xABCD))
            .Build();

        var result = await SendAsync(new FakeStunService(), request);

        AssertError(result, 420, UnknownAttributeReason, rfc5389: true);
        AssertReply(result, null, 4000, changeAddress: true, changePort: true);
    }

    [Fact]
    public async Task Optional_unknown_attribute_after_message_integrity_is_accepted()
    {
        var prefix = new RequestBuilder().Add(MessageAttributeType.UserName, User).Build();
        var request = Sign(prefix, PasswordBytes, sha256: false, RawAttribute(0x8022, "ok"u8.ToArray()));
        var service = Authorized(PasswordBytes);

        var result = await SendAsync(service, request);

        Assert.Equal(2, service.PasswordRequests);
        AssertSignedSuccess(result, PasswordBytes, sha256: false, rfc5389: true);
    }

    [Fact]
    public async Task Rfc5389_binding_response_uses_xor_origin_and_other_address()
    {
        var result = await SendAsync(new FakeStunService(), new RequestBuilder().Build());

        AssertBytes(result,
        [
            0x01, 0x01, 0x00, 0x30, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0xD4, 0x30, 0xCB, 0x00, 0x71, 0x05,
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xF5, 0x22, 0xEA, 0x12, 0xD5, 0x47,
            0x80, 0x2B, 0x00, 0x08, 0x00, 0x01, 0x0D, 0x96, 0xC0, 0x00, 0x02, 0x0A,
            0x80, 0x2C, 0x00, 0x08, 0x00, 0x01, 0x0D, 0x97, 0xC6, 0x33, 0x64, 0x14
        ]);
        AssertReply(result, null, 0, changeAddress: false, changePort: false);
    }

    [Fact]
    public async Task Rfc3489_binding_response_uses_source_and_changed_address()
    {
        var request = new RequestBuilder(rfc5389: false, classicPrefix: [0x11, 0x22, 0x33, 0x44]).Build();
        var result = await SendAsync(new FakeStunService(), request);

        AssertBytes(result,
        [
            0x01, 0x01, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0xD4, 0x30, 0xCB, 0x00, 0x71, 0x05,
            0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x0D, 0x96, 0xC0, 0x00, 0x02, 0x0A,
            0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x0D, 0x97, 0xC6, 0x33, 0x64, 0x14
        ]);
        Assert.NotNull(result.Response);
        Assert.NotEqual(new byte[] { 0x11, 0x22, 0x33, 0x44 }, result.Response.AsSpan(4, 4).ToArray());
    }

    [Fact]
    public async Task Reversed_magic_cookie_is_handled_as_rfc3489()
    {
        var request = new RequestBuilder(rfc5389: false, classicPrefix: [0x42, 0xA4, 0x12, 0x21]).Build();
        var result = await SendAsync(new FakeStunService(), request);
        var attributes = AssertSuccess(result, rfc5389: false, classicPrefixCleared: true);
        Assert.Equal(new ushort[] { 0x0001, 0x0004, 0x0005 }, attributes.Select(attribute => attribute.Type));
    }

    [Fact]
    public async Task Rfc5389_ipv6_addresses_are_xor_mapped_with_the_transaction_id()
    {
        var transactionId = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0 };
        var request = new RequestBuilder(transactionId: transactionId).Build();
        var result = await SendAsync(new FakeStunService(), request, RemoteV6, 2000, LocalV6, 3478, OtherV6, 3479);

        var attributes = AssertSuccess(result, rfc5389: true, transactionId: transactionId, classicPrefixCleared: false);
        AssertAddress(attributes[0], 0x0001, RemoteV6, 2000);
        AssertXorAddress(attributes[1], RemoteV6, 2000, transactionId);
        Assert.Equal(0x01, attributes[1].Value[4]);
        AssertAddress(attributes[2], 0x802B, LocalV6, 3478);
        AssertAddress(attributes[3], 0x802C, OtherV6, 3479);
    }

    [Fact]
    public async Task Xor_mapped_ipv4_ignores_the_transaction_id_and_ipv6_uses_it()
    {
        var firstId = Enumerable.Repeat((byte)0x11, 12).ToArray();
        var secondId = Enumerable.Repeat((byte)0x22, 12).ToArray();
        var first = await SendAsync(new FakeStunService(), new RequestBuilder(transactionId: firstId).Build(), RemoteV6);
        var second = await SendAsync(new FakeStunService(), new RequestBuilder(transactionId: secondId).Build(), RemoteV6);
        var firstV4 = await SendAsync(new FakeStunService(), new RequestBuilder(transactionId: firstId).Build());
        var secondV4 = await SendAsync(new FakeStunService(), new RequestBuilder(transactionId: secondId).Build());

        var firstAttributes = ReadAttributesStrict(first);
        var secondAttributes = ReadAttributesStrict(second);
        Assert.NotEqual(firstAttributes[1].Value, secondAttributes[1].Value);
        Assert.Equal(ReadAttributesStrict(firstV4)[1].Value, ReadAttributesStrict(secondV4)[1].Value);
    }

    [Fact]
    public async Task Mixed_address_families_keep_their_own_sizes()
    {
        var result = await SendAsync(new FakeStunService(), new RequestBuilder().Build(), RemoteV4, RemotePort, LocalV6, LocalPort, OtherV4, OtherPort);
        var attributes = AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);
        AssertAddress(attributes[0], 0x0001, RemoteV4, RemotePort);
        AssertXorAddress(attributes[1], RemoteV4, RemotePort, TxId);
        AssertAddress(attributes[2], 0x802B, LocalV6, LocalPort);
        AssertAddress(attributes[3], 0x802C, OtherV4, OtherPort);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(65535)]
    public async Task Mapped_port_is_written_and_xored(int port)
    {
        var result = await SendAsync(new FakeStunService(), new RequestBuilder().Build(), remotePort: (ushort)port);
        var attributes = AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);
        AssertAddress(attributes[0], 0x0001, RemoteV4, (ushort)port);
        AssertXorAddress(attributes[1], RemoteV4, (ushort)port, TxId);
    }

    [Fact]
    public async Task Rfc3489_reflected_from_uses_the_remote_address_while_the_result_uses_the_response_address()
    {
        var reply = new byte[] { 1, 2, 3, 4 };
        var request = new RequestBuilder(rfc5389: false)
            .Add(MessageAttributeType.ResponseAddress, AddressValue(1, 9, reply, reserved: 0xAB))
            .Build();

        var result = await SendAsync(new FakeStunService(), request);
        var attributes = AssertSuccess(result, rfc5389: false, classicPrefixCleared: true);

        Assert.Equal(new ushort[] { 0x0001, 0x0004, 0x0005, 0x000B }, attributes.Select(attribute => attribute.Type));
        AssertAddress(attributes[3], 0x000B, RemoteV4, RemotePort);
        AssertReply(result, reply, 9, changeAddress: false, changePort: false);
    }

    [Fact]
    public async Task Rfc5389_keeps_a_response_address_on_the_result_without_emitting_reflected_from()
    {
        var reply = new byte[] { 9, 8, 7, 6 };
        var request = new RequestBuilder()
            .Add(MessageAttributeType.ResponseAddress, AddressValue(1, 99, reply))
            .Add(MessageAttributeType.ChangeRequest, Change(0x06))
            .Build();

        var result = await SendAsync(new FakeStunService(), request);
        var attributes = AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);

        Assert.Equal(new ushort[] { 0x0001, 0x0020, 0x802B, 0x802C }, attributes.Select(attribute => attribute.Type));
        AssertReply(result, reply, 99, changeAddress: true, changePort: true);
    }

    [Fact]
    public async Task Rfc3489_ipv6_response_address_is_returned_and_reflected_from_stays_remote()
    {
        var reply = Enumerable.Range(1, 16).Select(value => (byte)value).ToArray();
        var request = new RequestBuilder(rfc5389: false)
            .Add(MessageAttributeType.ResponseAddress, AddressValue(2, 4444, reply))
            .Build();

        var result = await SendAsync(new FakeStunService(), request, RemoteV6, 5555, LocalV6, 3478, OtherV6, 3479);
        var attributes = AssertSuccess(result, rfc5389: false, classicPrefixCleared: true);

        AssertAddress(attributes[0], 0x0001, RemoteV6, 5555);
        AssertAddress(attributes[1], 0x0004, LocalV6, 3478);
        AssertAddress(attributes[2], 0x0005, OtherV6, 3479);
        AssertAddress(attributes[3], 0x000B, RemoteV6, 5555);
        AssertReply(result, reply, 4444, changeAddress: false, changePort: false);
    }

    [Fact]
    public async Task Response_address_with_port_zero_still_adds_reflected_from()
    {
        var reply = new byte[] { 8, 8, 8, 8 };
        var request = new RequestBuilder(rfc5389: false)
            .Add(MessageAttributeType.ResponseAddress, AddressValue(1, 0, reply))
            .Build();

        var result = await SendAsync(new FakeStunService(), request);
        var attributes = AssertSuccess(result, rfc5389: false, classicPrefixCleared: true);
        Assert.Contains(attributes, attribute => attribute.Type == 0x000B);
        AssertReply(result, reply, 0, changeAddress: false, changePort: false);
    }

    [Fact]
    public async Task Response_port_zero_does_not_add_reflected_from()
    {
        var request = new RequestBuilder(rfc5389: false).Add(MessageAttributeType.ResponsePort, PortValue(0, 0xFFFF)).Build();
        var result = await SendAsync(new FakeStunService(), request);
        var attributes = AssertSuccess(result, rfc5389: false, classicPrefixCleared: true);
        Assert.Equal(new ushort[] { 0x0001, 0x0004, 0x0005 }, attributes.Select(attribute => attribute.Type));
        AssertReply(result, null, 0, changeAddress: false, changePort: false);
    }

    [Fact]
    public async Task Response_port_reads_the_first_two_bytes_and_overrides_an_earlier_response_address()
    {
        var reply = new byte[] { 1, 2, 3, 4 };
        var request = new RequestBuilder(rfc5389: false)
            .Add(MessageAttributeType.ResponseAddress, AddressValue(1, 1000, reply))
            .Add(MessageAttributeType.ResponsePort, PortValue(2000, 0xABCD))
            .Build();

        var result = await SendAsync(new FakeStunService(), request);
        AssertSuccess(result, rfc5389: false, classicPrefixCleared: true);
        AssertReply(result, reply, 2000, changeAddress: false, changePort: false);
    }

    [Fact]
    public async Task Later_response_address_overrides_an_earlier_response_port()
    {
        var reply = new byte[] { 5, 6, 7, 8 };
        var request = new RequestBuilder(rfc5389: false)
            .Add(MessageAttributeType.ResponsePort, PortValue(2000))
            .Add(MessageAttributeType.ResponseAddress, AddressValue(1, 1000, reply))
            .Build();

        var result = await SendAsync(new FakeStunService(), request);
        AssertReply(result, reply, 1000, changeAddress: false, changePort: false);
    }

    [Fact]
    public async Task Extra_response_address_bytes_are_ignored()
    {
        var ipv4 = AddressValue(1, 42, [9, 9, 9, 9]);
        var longer = new byte[ipv4.Length + 2];
        ipv4.CopyTo(longer);
        longer[^2] = 0xEE;
        longer[^1] = 0xFF;
        var request = new RequestBuilder().Add(MessageAttributeType.ResponseAddress, longer).Build();

        var result = await SendAsync(new FakeStunService(), request);
        AssertReply(result, [9, 9, 9, 9], 42, changeAddress: false, changePort: false);
    }

    [Theory]
    [MemberData(nameof(InvalidResponseAddresses))]
    public async Task Invalid_response_address_discards_the_request(byte[] value)
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.ChangeRequest, Change(0x06))
            .Add(MessageAttributeType.ResponseAddress, value)
            .Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    public static IEnumerable<object[]> InvalidResponseAddresses()
    {
        yield return new object[] { Array.Empty<byte>() };
        yield return new object[] { new byte[3] };
        yield return new object[] { AddressValue(1, 1, [1, 2, 3]) };
        yield return new object[] { AddressValue(2, 1, new byte[15]) };
        yield return new object[] { AddressValue(0, 1, [1, 2, 3, 4]) };
        yield return new object[] { AddressValue(3, 1, [1, 2, 3, 4]) };
        yield return new object[] { AddressValue(2, 1, [1, 2, 3, 4]) };
    }

    [Theory]
    [InlineData(0x00, false, false)]
    [InlineData(0x01, false, false)]
    [InlineData(0x02, false, true)]
    [InlineData(0x04, true, false)]
    [InlineData(0x06, true, true)]
    [InlineData(0x08, false, false)]
    [InlineData(0xFF, true, true)]
    public async Task Change_request_uses_only_the_port_and_address_bits(int flags, bool changeAddress, bool changePort)
    {
        var request = new RequestBuilder().Add(MessageAttributeType.ChangeRequest, Change((byte)flags)).Build();
        var result = await SendAsync(new FakeStunService(), request);
        AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);
        AssertReply(result, null, 0, changeAddress, changePort);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(8)]
    public async Task Invalid_change_request_length_discards_the_request(int length)
    {
        var request = new RequestBuilder().Add(MessageAttributeType.ChangeRequest, new byte[length]).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Change_request_flags_accumulate_and_are_not_cleared()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.ChangeRequest, Change(0x02))
            .Add(MessageAttributeType.ChangeRequest, Change(0x04))
            .Add(MessageAttributeType.ChangeRequest, Change(0x00))
            .Build();
        var result = await SendAsync(new FakeStunService(), request);
        AssertReply(result, null, 0, changeAddress: true, changePort: true);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(8)]
    public async Task Invalid_response_port_length_discards_the_request(int length)
    {
        var request = new RequestBuilder().Add(MessageAttributeType.ResponsePort, new byte[length]).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Duplicate_username_realm_nonce_or_password_algorithm_discards_parsed_state()
    {
        byte[][] requests =
        [
            new RequestBuilder().Add(MessageAttributeType.ChangeRequest, Change(0x06)).Add(MessageAttributeType.UserName, User).Add(MessageAttributeType.UserName, User).Build(),
            new RequestBuilder().Add(MessageAttributeType.ChangeRequest, Change(0x06)).Add(MessageAttributeType.Realm, RealmName).Add(MessageAttributeType.Realm, RealmName).Build(),
            new RequestBuilder().Add(MessageAttributeType.ChangeRequest, Change(0x06)).Add(MessageAttributeType.Nonce, new byte[112]).Add(MessageAttributeType.Nonce, new byte[112]).Build(),
            new RequestBuilder().Add(MessageAttributeType.ChangeRequest, Change(0x06)).Add(MessageAttributeType.PasswordAlgorithm, Algorithm(MessageExtensions.PasswordAlgorithmMd5)).Add(MessageAttributeType.PasswordAlgorithm, Algorithm(MessageExtensions.PasswordAlgorithmSha256)).Build()
        ];

        foreach (var request in requests)
            AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Empty_username_realm_and_nonce_can_be_repeated()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.UserName, [])
            .Add(MessageAttributeType.UserName, [])
            .Add(MessageAttributeType.Realm, [])
            .Add(MessageAttributeType.Realm, [])
            .Add(MessageAttributeType.Nonce, [])
            .Add(MessageAttributeType.Nonce, [])
            .Add(MessageAttributeType.ChangeRequest, Change(0x02))
            .Build();

        var result = await SendAsync(new FakeStunService(), request);
        AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);
        AssertReply(result, null, 0, changeAddress: false, changePort: true);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(3, 0)]
    [InlineData(1, 1)]
    [InlineData(2, 4)]
    public async Task Invalid_password_algorithm_discards_the_request(int algorithm, int parameterLength)
    {
        var value = new byte[parameterLength == 4 ? 8 : 4];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)algorithm);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), (ushort)parameterLength);
        var request = new RequestBuilder().Add(MessageAttributeType.ChangeRequest, Change(0x06)).Add(MessageAttributeType.PasswordAlgorithm, value).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Password_algorithm_shorter_than_four_bytes_is_discarded()
    {
        var request = new RequestBuilder().Add(MessageAttributeType.PasswordAlgorithm, [0, 1]).Build();
        AssertDiscarded(await SendAsync(new FakeStunService(), request));
    }

    [Fact]
    public async Task Password_algorithms_attribute_is_ignored()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.PasswordAlgorithms, [])
            .Add(MessageAttributeType.PasswordAlgorithms, [1, 2, 3])
            .Add(MessageAttributeType.ChangeRequest, Change(0x04))
            .Build();
        var result = await SendAsync(new FakeStunService(), request);
        AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);
        Assert.True(result.ChangeAddress);
    }

    [Theory]
        [InlineData(false, false, true)]
        [InlineData(true, false, false)]
        [InlineData(false, true, false)]
        [InlineData(true, true, true)]
    public async Task Password_algorithm_must_match_the_integrity_length(bool sha256Algorithm, bool sha256Integrity, bool success)
    {
        var builder = new RequestBuilder().Add(MessageAttributeType.PasswordAlgorithm, Algorithm(sha256Algorithm ? MessageExtensions.PasswordAlgorithmSha256 : MessageExtensions.PasswordAlgorithmMd5));
        if (sha256Integrity)
            builder.Add(MessageAttributeType.MessageIntegritySHA256, new byte[32]);
        else
            builder.Add(MessageAttributeType.MessageIntegrity, new byte[20]);
        var result = await SendAsync(new FakeStunService(), builder.Build());

        if (success)
            AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);
        else
            AssertError(result, 400, BadRequest, rfc5389: true);
    }

    [Fact]
    public async Task Password_algorithm_without_integrity_is_a_bad_request()
    {
        var md5 = new RequestBuilder().Add(MessageAttributeType.PasswordAlgorithm, Algorithm(MessageExtensions.PasswordAlgorithmMd5)).Build();
        var sha256 = new RequestBuilder().Add(MessageAttributeType.PasswordAlgorithm, Algorithm(MessageExtensions.PasswordAlgorithmSha256)).Build();
        AssertError(await SendAsync(new FakeStunService(), md5), 400, BadRequest, rfc5389: true);
        AssertBytes(await SendAsync(new FakeStunService(), sha256),
        [
            0x01, 0x11, 0x00, 0x14, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x00, 0x09, 0x00, 0x0F, 0x00, 0x00, 0x04, 0x00, 0x42, 0x61, 0x64, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x00
        ]);
    }

    [Fact]
    public async Task Integrity_without_a_password_algorithm_is_left_unsigned_when_authorization_is_off()
    {
        var request = new RequestBuilder().Add(MessageAttributeType.UserName, User).Add(MessageAttributeType.MessageIntegrity, new byte[20]).Build();
        var service = new FakeStunService();
        var result = await SendAsync(service, request);
        var attributes = AssertSuccess(result, rfc5389: true, classicPrefixCleared: false);
        Assert.DoesNotContain(attributes, attribute => attribute.Type is (ushort)0x0008 or (ushort)0x001C);
        Assert.Equal(0, service.PasswordRequests);
    }

    [Fact]
    public async Task Required_attribute_after_message_integrity_is_a_bad_request_and_keeps_parsed_state()
    {
        var prefix = new RequestBuilder()
            .Add(MessageAttributeType.ChangeRequest, Change(0x02))
            .Add(MessageAttributeType.UserName, User)
            .Build();
        var request = AppendRaw(Sign(prefix, PasswordBytes, sha256: false), RawAttribute(MessageAttributeType.ResponsePort, PortValue(3210)));
        var service = new ThrowingAuthService();

        var result = await SendAsync(service, request);

        AssertError(result, 400, BadRequest, rfc5389: true);
        AssertReply(result, null, 3210, changeAddress: false, changePort: true);
    }

    [Fact]
    public async Task Unknown_required_attribute_after_integrity_is_400_rather_than_420()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .AddRaw(0x000D, [])
            .Build();
        var attributes = AssertError(await SendAsync(new ThrowingAuthService(), request), 400, BadRequest, rfc5389: true);
        Assert.Single(attributes);
    }

    [Fact]
    public async Task Unknown_required_attribute_before_integrity_is_420_and_skips_authorization()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.ChangeRequest, Change(0x04))
            .AddRaw(0x000D, [])
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        var result = await SendAsync(new ThrowingAuthService(), request);
        AssertError(result, 420, UnknownAttributeReason, rfc5389: true);
        Assert.True(result.ChangeAddress);
    }

    [Fact]
    public async Task Unpaired_algorithm_wins_over_authorization()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.PasswordAlgorithm, Algorithm(MessageExtensions.PasswordAlgorithmSha256))
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        AssertError(await SendAsync(new ThrowingAuthService(), request), 400, BadRequest, rfc5389: true);
    }

    [Fact]
    public async Task Sha256_integrity_followed_by_sha1_is_a_bad_request()
    {
        var prefix = new RequestBuilder().Add(MessageAttributeType.UserName, User).Build();
        var request = AppendRaw(Sign(prefix, PasswordBytes, sha256: true), RawAttribute(MessageAttributeType.MessageIntegrity, new byte[20]));
        var service = Authorized(PasswordBytes);
        var attributes = AssertError(await SendAsync(service, request), 400, BadRequest, rfc5389: true);
        Assert.Single(attributes);
        Assert.Equal(0, service.PasswordRequests);
    }

    [Fact]
    public async Task Sha1_followed_by_sha256_authorizes_with_the_sha256_key()
    {
        var prefix = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.MessageIntegrity, Enumerable.Repeat((byte)0x11, 20).ToArray())
            .Build();
        var request = Sign(prefix, PasswordBytes, sha256: true);
        var service = Authorized(PasswordBytes);

        var result = await SendAsync(service, request);

        Assert.Equal(2, service.PasswordRequests);
        AssertSignedSuccess(result, PasswordBytes, sha256: true, rfc5389: true);
    }

    [Fact]
    public async Task Same_service_can_answer_rfc5389_and_then_rfc3489()
    {
        var service = new FakeStunService();
        var modern = await SendAsync(service, new RequestBuilder().Build());
        var classic = await SendAsync(service, new RequestBuilder(rfc5389: false).Build());

        AssertSuccess(modern, rfc5389: true, classicPrefixCleared: false);
        AssertSuccess(classic, rfc5389: false, classicPrefixCleared: true);
    }

    [Fact]
    public async Task Short_term_missing_credentials_are_unauthorized_without_a_challenge()
    {
        var service = Authorized(PasswordBytes);
        var requests = new[]
        {
            new RequestBuilder().Build(),
            new RequestBuilder().Add(MessageAttributeType.UserName, User).Build(),
            new RequestBuilder().Add(MessageAttributeType.MessageIntegrity, new byte[20]).Build(),
            new RequestBuilder().Add(MessageAttributeType.UserName, []).Add(MessageAttributeType.MessageIntegrity, new byte[20]).Build()
        };

        foreach (var request in requests)
        {
            var result = await SendAsync(service, request);
            var attributes = AssertError(result, 401, Unauthorized, rfc5389: true);
            Assert.Single(attributes);
        }

        Assert.Equal(0, service.PasswordRequests);
        AssertBytes(await SendAsync(Authorized(PasswordBytes), requests[1]),
        [
            0x01, 0x11, 0x00, 0x14, 0x21, 0x12, 0xA4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x00, 0x09, 0x00, 0x10, 0x00, 0x00, 0x04, 0x01, 0x55, 0x6E, 0x61, 0x75, 0x74, 0x68, 0x6F, 0x72, 0x69, 0x7A, 0x65, 0x64
        ]);
    }

    [Fact]
    public async Task Short_term_wrong_password_is_unauthorized_after_one_lookup()
    {
        var request = Sign(new RequestBuilder().Add(MessageAttributeType.UserName, User).Build(), "wrong"u8.ToArray(), sha256: false);
        var service = Authorized(PasswordBytes);
        var attributes = AssertError(await SendAsync(service, request), 401, Unauthorized, rfc5389: true);
        Assert.Single(attributes);
        Assert.Equal(1, service.PasswordRequests);
        Assert.Equal(User, service.SeenUsers[0]);
    }

    [Fact]
    public async Task Short_term_username_must_match_byte_for_byte()
    {
        var request = Sign(new RequestBuilder().Add(MessageAttributeType.UserName, "User"u8.ToArray()).Build(), PasswordBytes, sha256: false);
        var service = Authorized(PasswordBytes);
        service.Lookup = (username, _) => username.Span.SequenceEqual(User) ? PasswordBytes : ReadOnlyMemory<byte>.Empty;
        var attributes = AssertError(await SendAsync(service, request), 401, Unauthorized, rfc5389: true);
        Assert.Single(attributes);
        Assert.Equal("User"u8.ToArray(), service.SeenUsers[0]);
    }

    [Fact]
    public async Task Short_term_sha1_success_signs_the_classic_response_with_the_password()
    {
        var request = new RequestBuilder(rfc5389: false)
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.ChangeRequest, Change(0x06))
            .Build();
        request = Sign(request, PasswordBytes, sha256: false);
        var service = Authorized(PasswordBytes);

        var result = await SendAsync(service, request);

        Assert.Equal(2, service.PasswordRequests);
        Assert.Equal(User, service.SeenUsers[0]);
        Assert.Equal(User, service.SeenUsers[1]);
        Assert.True(result.ChangeAddress);
        Assert.True(result.ChangePort);
        var attributes = AssertSignedSuccess(result, PasswordBytes, sha256: false, rfc5389: false);
        Assert.Equal(new ushort[] { 0x0001, 0x0004, 0x0005, 0x0008 }, attributes.Select(attribute => attribute.Type));
        Assert.False(MessageExtensions.VerifyMessageIntegrity(SignedPrefix(result, false), LongTermKey(User, RealmName, PasswordBytes, false), IntegrityHash(result, false)));
    }

    [Fact]
    public async Task Short_term_sha256_success_signs_with_sha256()
    {
        var request = Sign(new RequestBuilder().Add(MessageAttributeType.UserName, User).Build(), PasswordBytes, sha256: true);
        var service = Authorized(PasswordBytes);
        var result = await SendAsync(service, request);
        AssertSignedSuccess(result, PasswordBytes, sha256: true, rfc5389: true);
        Assert.False(MessageExtensions.VerifyMessageIntegrity(SignedPrefix(result, true), PasswordBytes, IntegrityHash(result, false)));
    }

    [Fact]
    public async Task Short_term_response_is_signed_with_the_second_password_lookup()
    {
        var first = PasswordBytes;
        var second = "second-password"u8.ToArray();
        var request = Sign(new RequestBuilder().Add(MessageAttributeType.UserName, User).Build(), first, sha256: false);
        var service = Authorized(first);
        service.Lookup = (_, call) => call == 0 ? first : second;

        var result = await SendAsync(service, request);

        AssertSignedSuccess(result, second, sha256: false, rfc5389: true);
        Assert.False(MessageExtensions.VerifyMessageIntegrity(SignedPrefix(result, false), first, IntegrityHash(result, false)));
    }

    [Fact]
    public async Task Short_term_empty_second_password_lookup_is_unauthorized_without_a_challenge()
    {
        var request = Sign(new RequestBuilder().Add(MessageAttributeType.UserName, User).Build(), PasswordBytes, sha256: false);
        var service = Authorized(PasswordBytes);
        service.Lookup = (_, call) => call == 0 ? PasswordBytes : ReadOnlyMemory<byte>.Empty;

        var attributes = AssertError(await SendAsync(service, request), 401, Unauthorized, rfc5389: true);

        Assert.Single(attributes);
        Assert.Equal(2, service.PasswordRequests);
    }

    [Fact]
    public async Task Default_password_provider_is_used_only_when_short_term_verification_runs()
    {
        var open = new ThrowingAuthService();
        AssertError(await SendAsync(open, new RequestBuilder().Add(MessageAttributeType.UserName, User).Build()), 401, Unauthorized, rfc5389: true);
        var signed = Sign(new RequestBuilder().Add(MessageAttributeType.UserName, User).Build(), PasswordBytes, sha256: false);
        await Assert.ThrowsAsync<NotSupportedException>(() => SendAsync(new ThrowingAuthService(), signed));
    }

    [Theory]
    [InlineData(false, true, true, true)]
    [InlineData(true, false, true, true)]
    [InlineData(true, true, false, true)]
    [InlineData(true, true, true, false)]
    public async Task Long_term_missing_material_is_a_challenge(bool user, bool realm, bool nonce, bool integrity)
    {
        var builder = new RequestBuilder();
        if (user)
            builder.Add(MessageAttributeType.UserName, User);
        if (realm)
            builder.Add(MessageAttributeType.Realm, RealmName);
        if (nonce)
            builder.Add(MessageAttributeType.Nonce, MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120));
        if (integrity)
            builder.Add(MessageAttributeType.MessageIntegrity, new byte[20]);
        var service = LongTerm();

        var attributes = AssertError(await SendAsync(service, builder.Build()), 401, Unauthorized, rfc5389: true);

        AssertChallenge(attributes, RealmName);
        Assert.Equal(0, service.PasswordRequests);
    }

    [Fact]
    public async Task Long_term_zero_length_fields_count_as_missing()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.UserName, [])
            .Add(MessageAttributeType.Realm, [])
            .Add(MessageAttributeType.Nonce, [])
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        var attributes = AssertError(await SendAsync(LongTerm(), request), 401, Unauthorized, rfc5389: true);
        AssertChallenge(attributes, RealmName);
    }

    [Fact]
    public async Task Long_term_realm_must_match_exactly()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.Realm, "Example.org"u8.ToArray())
            .Add(MessageAttributeType.Nonce, MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120))
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        var service = LongTerm();
        var attributes = AssertError(await SendAsync(service, request), 401, Unauthorized, rfc5389: true);
        AssertChallenge(attributes, RealmName);
        Assert.Equal(0, service.PasswordRequests);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(111)]
    [InlineData(113)]
    public async Task Long_term_nonce_with_the_wrong_length_is_stale(int length)
    {
        await AssertStaleNonce(new byte[length]);
    }

    [Fact]
    public async Task Long_term_zero_length_nonce_is_missing_rather_than_stale()
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.Realm, RealmName)
            .Add(MessageAttributeType.Nonce, [])
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        var service = LongTerm();
        var attributes = AssertError(await SendAsync(service, request), 401, Unauthorized, rfc5389: true);
        AssertChallenge(attributes, RealmName);
        Assert.Equal(0, service.PasswordRequests);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(48)]
    public async Task Long_term_nonce_with_invalid_hex_is_stale(int corruptOffset)
    {
        await AssertStaleNonce(MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120, corruptOffset: corruptOffset));
    }

    [Fact]
    public async Task Long_term_nonce_with_a_bad_mac_or_expired_timestamp_is_stale()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await AssertStaleNonce(MakeNonce(now + 120, corruptMac: true));
        await AssertStaleNonce(MakeNonce(now - 30));
    }

    [Fact]
    public async Task Stale_nonce_wins_over_a_bad_password_and_issues_a_new_nonce()
    {
        var nonce = MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 30);
        var request = LongTermRequest(PasswordBytes, nonce: nonce);
        var service = LongTerm();
        var attributes = AssertError(await SendAsync(service, request), 438, StaleNonce, rfc5389: true);
        AssertChallenge(attributes, RealmName);
        Assert.NotEqual(nonce, attributes[2].Value);
        Assert.Equal(0, service.PasswordRequests);
    }

    [Fact]
    public async Task Long_term_bad_password_is_a_challenge_after_the_nonce_is_accepted()
    {
        var request = LongTermRequest("wrong"u8.ToArray());
        var service = LongTerm();
        var attributes = AssertError(await SendAsync(service, request), 401, Unauthorized, rfc5389: true);
        AssertChallenge(attributes, RealmName);
        Assert.Equal(1, service.PasswordRequests);
    }

    [Fact]
    public async Task Long_term_signature_must_use_the_derived_key()
    {
        var unsigned = LongTermUnsigned();
        var request = Sign(unsigned, PasswordBytes, sha256: false);
        var attributes = AssertError(await SendAsync(LongTerm(), request), 401, Unauthorized, rfc5389: true);
        AssertChallenge(attributes, RealmName);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Long_term_success_signs_with_the_derived_key(bool sha256)
    {
        var request = LongTermRequest(PasswordBytes, sha256, includeAlgorithm: true);
        var service = LongTerm();
        var result = await SendAsync(service, request);
        var key = LongTermKey(User, RealmName, PasswordBytes, sha256);

        Assert.Equal(2, service.PasswordRequests);
        AssertSignedSuccess(result, key, sha256, rfc5389: true);
        Assert.False(MessageExtensions.VerifyMessageIntegrity(SignedPrefix(result, sha256), PasswordBytes, IntegrityHash(result, sha256)));
        Assert.Equal(new ushort[] { 0x0001, 0x0020, 0x802B, 0x802C, sha256 ? (ushort)0x001C : (ushort)0x0008 }, ReadAttributesStrict(result).Select(attribute => attribute.Type));
    }

    [Fact]
    public async Task Long_term_accepts_upper_and_mixed_case_nonces()
    {
        var upper = LongTermRequest(PasswordBytes, nonce: MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120, upper: true));
        var mixed = MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120);
        mixed[0] = (byte)char.ToUpperInvariant((char)mixed[0]);
        mixed[40] = (byte)char.ToUpperInvariant((char)mixed[40]);
        mixed[80] = (byte)char.ToUpperInvariant((char)mixed[80]);

        AssertSignedSuccess(await SendAsync(LongTerm(), upper), LongTermKey(User, RealmName, PasswordBytes, false), sha256: false, rfc5389: true);
        AssertSignedSuccess(await SendAsync(LongTerm(), LongTermRequest(PasswordBytes, nonce: mixed)), LongTermKey(User, RealmName, PasswordBytes, false), sha256: false, rfc5389: true);
    }

    [Fact]
    public async Task Long_term_padded_username_and_realm_omit_the_padding()
    {
        var user = "abc"u8.ToArray();
        var realm = "xy"u8.ToArray();
        var unsigned = new RequestBuilder()
            .Add(MessageAttributeType.UserName, user)
            .Add(MessageAttributeType.Realm, realm)
            .Add(MessageAttributeType.Nonce, MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120))
            .Build();
        var request = Sign(unsigned, LongTermKey(user, realm, PasswordBytes, false), sha256: false);
        var service = LongTerm(realm);

        var result = await SendAsync(service, request);

        Assert.Equal(user, service.SeenUsers[0]);
        Assert.Equal(3, service.SeenUsers[0].Length);
        AssertSignedSuccess(result, LongTermKey(user, realm, PasswordBytes, false), sha256: false, rfc5389: true);
    }

    [Fact]
    public async Task Long_term_empty_second_password_lookup_challenges()
    {
        var request = LongTermRequest(PasswordBytes);
        var service = LongTerm();
        service.Lookup = (_, call) => call == 0 ? PasswordBytes : ReadOnlyMemory<byte>.Empty;
        var attributes = AssertError(await SendAsync(service, request), 401, Unauthorized, rfc5389: true);
        AssertChallenge(attributes, RealmName);
        Assert.Equal(2, service.PasswordRequests);
    }

    [Fact]
    public async Task Long_term_verification_is_skipped_until_the_nonce_is_current()
    {
        var service = new ThrowingAuthService { Realm = RealmName };
        var missing = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.Realm, RealmName)
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        AssertError(await SendAsync(service, missing), 401, Unauthorized, rfc5389: true);

        var stale = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.Realm, RealmName)
            .Add(MessageAttributeType.Nonce, MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 30))
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        var attributes = AssertError(await SendAsync(service, stale), 438, StaleNonce, rfc5389: true);
        AssertChallenge(attributes, RealmName);

        var current = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.Realm, RealmName)
            .Add(MessageAttributeType.Nonce, MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120))
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        await Assert.ThrowsAsync<NotSupportedException>(() => SendAsync(new ThrowingAuthService { Realm = RealmName }, current));
    }

    [Fact]
    public async Task Integrity_beyond_the_verification_buffer_is_unauthorized()
    {
        var filler = new byte[60000];
        var unsigned = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.Realm, RealmName)
            .Add(MessageAttributeType.Nonce, MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120))
            .AddRaw(0x8000, filler)
            .Build();
        var request = Sign(unsigned, LongTermKey(User, RealmName, PasswordBytes, false), sha256: false);
        var service = LongTerm();

        var attributes = AssertError(await SendAsync(service, request), 401, Unauthorized, rfc5389: true);

        AssertChallenge(attributes, RealmName);
        Assert.Equal(0, service.PasswordRequests);
    }

    private static async Task AssertStaleNonce(byte[] nonce)
    {
        var request = new RequestBuilder()
            .Add(MessageAttributeType.UserName, User)
            .Add(MessageAttributeType.Realm, RealmName)
            .Add(MessageAttributeType.Nonce, nonce)
            .Add(MessageAttributeType.MessageIntegrity, new byte[20])
            .Build();
        var service = LongTerm();
        var attributes = AssertError(await SendAsync(service, request), 438, StaleNonce, rfc5389: true);
        AssertChallenge(attributes, RealmName);
        Assert.Equal(0, service.PasswordRequests);
    }

    private static FakeStunService Authorized(byte[] password) => new() { Authorize = true, Password = password };

    private static FakeStunService LongTerm(byte[]? realm = null) => new()
    {
        Authorize = true,
        Realm = realm ?? RealmName,
        Password = PasswordBytes
    };

    private static byte[] LongTermUnsigned(byte[]? nonce = null, byte[]? user = null, byte[]? realm = null, bool sha256 = false, bool includeAlgorithm = false)
    {
        user ??= User;
        realm ??= RealmName;
        var builder = new RequestBuilder()
            .Add(MessageAttributeType.UserName, user)
            .Add(MessageAttributeType.Realm, realm)
            .Add(MessageAttributeType.Nonce, nonce ?? MakeNonce(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120));
        if (includeAlgorithm)
            builder.Add(MessageAttributeType.PasswordAlgorithm, Algorithm(sha256 ? MessageExtensions.PasswordAlgorithmSha256 : MessageExtensions.PasswordAlgorithmMd5));
        return builder.Build();
    }

    private static byte[] LongTermRequest(byte[] password, bool sha256 = false, byte[]? nonce = null, bool includeAlgorithm = false)
    {
        var user = User;
        var realm = RealmName;
        return Sign(LongTermUnsigned(nonce, user, realm, sha256, includeAlgorithm), LongTermKey(user, realm, password, sha256), sha256);
    }

    private static void AssertDiscarded(StunRequestResult result)
    {
        Assert.Null(result.Response);
        Assert.Equal(0, result.ResponseLength);
        Assert.True(result.ResponseAddress.IsEmpty);
        Assert.Equal(0, result.ResponsePort);
        Assert.False(result.ChangeAddress);
        Assert.False(result.ChangePort);
    }

    private static List<StunAttr> AssertSuccess(StunRequestResult result, bool rfc5389, bool classicPrefixCleared, byte[]? transactionId = null)
    {
        AssertHeader(result, MessageType.Response, rfc5389, transactionId ?? TxId, classicPrefixCleared);
        return ReadAttributesStrict(result);
    }

    private static List<StunAttr> AssertError(StunRequestResult result, ushort code, string reason, bool rfc5389, byte[]? transactionId = null)
    {
        AssertHeader(result, MessageType.Error, rfc5389, transactionId ?? TxId, classicPrefixCleared: !rfc5389);
        var attributes = ReadAttributesStrict(result);
        Assert.NotEmpty(attributes);
        Assert.Equal(0x0009, attributes[0].Type);
        Assert.Equal(0, attributes[0].Value[0]);
        Assert.Equal(0, attributes[0].Value[1]);
        Assert.Equal(code, (ushort)(attributes[0].Value[2] * 100 + attributes[0].Value[3]));
        Assert.Equal(reason, Encoding.UTF8.GetString(attributes[0].Value.AsSpan(4)));
        return attributes;
    }

    private static List<StunAttr> AssertSignedSuccess(StunRequestResult result, byte[] key, bool sha256, bool rfc5389)
    {
        AssertHeader(result, MessageType.Response, rfc5389, TxId, classicPrefixCleared: false);
        var attributes = ReadAttributesStrict(result);
        var hashLength = sha256 ? 32 : 20;
        Assert.Equal(sha256 ? (ushort)0x001C : (ushort)0x0008, attributes[^1].Type);
        Assert.Equal(hashLength, attributes[^1].Value.Length);
        Assert.True(MessageExtensions.VerifyMessageIntegrity(SignedPrefix(result, sha256), key, IntegrityHash(result, sha256)));
        return attributes;
    }

    private static void AssertChallenge(IReadOnlyList<StunAttr> attributes, byte[] realm)
    {
        Assert.Equal(4, attributes.Count);
        Assert.Equal(0x0014, attributes[1].Type);
        Assert.Equal(realm, attributes[1].Value);
        Assert.Equal(0x0015, attributes[2].Type);
        AssertCurrentNonce(attributes[2].Value);
        Assert.Equal(0x8002, attributes[3].Type);
        Assert.Equal(new byte[] { 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 }, attributes[3].Value);
    }

    private static void AssertHeader(StunRequestResult result, MessageType type, bool rfc5389, byte[] transactionId, bool classicPrefixCleared)
    {
        Assert.NotNull(result.Response);
        Assert.InRange(result.ResponseLength, 20, result.Response.Length);
        Assert.Equal(BinaryPrimitives.ReverseEndianness((ushort)type), BinaryPrimitives.ReadUInt16BigEndian(result.Response.AsSpan(0)));
        Assert.Equal(result.ResponseLength - 20, BinaryPrimitives.ReadUInt16BigEndian(result.Response.AsSpan(2)));
        if (rfc5389)
            Assert.Equal(MagicCookie, result.Response.AsSpan(4, 4).ToArray());
        else if (classicPrefixCleared)
            Assert.Equal(new byte[] { 0, 0, 0, 0 }, result.Response.AsSpan(4, 4).ToArray());
        Assert.Equal(transactionId, result.Response.AsSpan(8, 12).ToArray());
    }

    private static void AssertBytes(StunRequestResult result, byte[] expected)
    {
        Assert.NotNull(result.Response);
        Assert.Equal(expected.Length, result.ResponseLength);
        Assert.Equal(expected, result.Response.AsSpan(0, result.ResponseLength).ToArray());
    }

    private static void AssertAddress(StunAttr attribute, ushort wireType, byte[] address, ushort port, bool reservedZero = true)
    {
        Assert.Equal(wireType, attribute.Type);
        Assert.Equal(address.Length == 4 ? 8 : 20, attribute.Value.Length);
        if (reservedZero)
            Assert.Equal(0, attribute.Value[0]);
        Assert.Equal(address.Length == 4 ? (byte)1 : (byte)2, attribute.Value[1]);
        Assert.Equal(port, BinaryPrimitives.ReadUInt16BigEndian(attribute.Value.AsSpan(2)));
        Assert.Equal(address, attribute.Value.AsSpan(4).ToArray());
    }

    private static void AssertXorAddress(StunAttr attribute, byte[] address, ushort port, byte[] transactionId)
    {
        Assert.Equal(0x0020, attribute.Type);
        Assert.Equal(address.Length == 4 ? (byte)1 : (byte)2, attribute.Value[1]);
        Assert.Equal((ushort)(port ^ 0x2112), BinaryPrimitives.ReadUInt16BigEndian(attribute.Value.AsSpan(2)));
        Assert.Equal(Xor(address, transactionId), attribute.Value.AsSpan(4).ToArray());
    }

    private static void AssertReply(StunRequestResult result, byte[]? address, ushort port, bool changeAddress, bool changePort)
    {
        if (address is null)
            Assert.True(result.ResponseAddress.IsEmpty);
        else
            Assert.Equal(address, result.ResponseAddress.ToArray());
        Assert.Equal(port, result.ResponsePort);
        Assert.Equal(changeAddress, result.ChangeAddress);
        Assert.Equal(changePort, result.ChangePort);
    }

    private static List<StunAttr> ReadAttributesStrict(StunRequestResult result)
    {
        Assert.NotNull(result.Response);
        var message = result.Response;
        var end = result.ResponseLength;
        var attributes = new List<StunAttr>();
        var offset = 20;
        while (offset < end)
        {
            Assert.True(end - offset >= 4, $"Truncated attribute header at offset {offset}.");
            var type = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(offset));
            var length = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(offset + 2));
            var padded = 4 + Pad(length);
            Assert.True(offset + padded <= end, $"Attribute 0x{type:X4} overruns the response.");
            attributes.Add(new StunAttr(type, message.AsSpan(offset + 4, length).ToArray()));
            offset += padded;
        }

        Assert.Equal(end, offset);
        return attributes;
    }

    private static ReadOnlySpan<byte> SignedPrefix(StunRequestResult result, bool sha256)
    {
        var attributeSize = sha256 ? 36 : 24;
        return result.Response.AsSpan(0, result.ResponseLength - attributeSize);
    }

    private static ReadOnlySpan<byte> IntegrityHash(StunRequestResult result, bool sha256)
    {
        var hashLength = sha256 ? 32 : 20;
        return result.Response.AsSpan(result.ResponseLength - hashLength, hashLength);
    }

    private static void AssertCurrentNonce(byte[] nonce)
    {
        Assert.Equal(112, nonce.Length);
        var key = FromHex(nonce.AsSpan(0, 32));
        var expiry = FromHex(nonce.AsSpan(32, 16));
        var mac = FromHex(nonce.AsSpan(48));
        Assert.Equal(HMACSHA256.HashData(key, expiry), mac);
        var expires = BinaryPrimitives.ReadInt64BigEndian(expiry);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.InRange(expires, now, now + 605);
    }

    private static byte[] MakeNonce(long expiryUnix, bool upper = false, int corruptOffset = -1, bool corruptMac = false)
    {
        var key = RandomNumberGenerator.GetBytes(16);
        var expiry = new byte[8];
        BinaryPrimitives.WriteInt64BigEndian(expiry, expiryUnix);
        var mac = HMACSHA256.HashData(key, expiry);
        if (corruptMac)
            mac[0] ^= 0xFF;
        var nonce = new byte[112];
        EncodeHex(key, nonce.AsSpan(0, 32), upper);
        EncodeHex(expiry, nonce.AsSpan(32, 16), upper);
        EncodeHex(mac, nonce.AsSpan(48), upper);
        if (corruptOffset >= 0)
            nonce[corruptOffset] = (byte)'g';
        return nonce;
    }

    private static byte[] Sign(byte[] unsigned, ReadOnlySpan<byte> key, bool sha256, byte[]? suffix = null)
    {
        suffix ??= [];
        var offset = unsigned.Length;
        var hashLength = sha256 ? 32 : 20;
        var attributeSize = hashLength + 4;
        var input = unsigned.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(2), (ushort)(offset - 20 + attributeSize));
        var hash = sha256 ? HMACSHA256.HashData(key, input) : HMACSHA1.HashData(key, input);
        var signed = new byte[offset + attributeSize + suffix.Length];
        unsigned.CopyTo(signed, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(signed.AsSpan(offset), (ushort)(sha256 ? MessageAttributeType.MessageIntegritySHA256 : MessageAttributeType.MessageIntegrity));
        BinaryPrimitives.WriteUInt16BigEndian(signed.AsSpan(offset + 2), (ushort)hashLength);
        hash.CopyTo(signed.AsSpan(offset + 4));
        suffix.CopyTo(signed, offset + attributeSize);
        BinaryPrimitives.WriteUInt16BigEndian(signed.AsSpan(2), (ushort)(signed.Length - 20));
        return signed;
    }

    private static byte[] AppendRaw(byte[] message, byte[] attribute)
    {
        var result = new byte[message.Length + attribute.Length];
        message.CopyTo(result, 0);
        attribute.CopyTo(result, message.Length);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), (ushort)(result.Length - 20));
        return result;
    }

    private static byte[] RawAttribute(ushort wire, byte[] value)
    {
        var raw = new byte[4 + Pad(value.Length)];
        BinaryPrimitives.WriteUInt16BigEndian(raw, wire);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(2), (ushort)value.Length);
        value.CopyTo(raw.AsSpan(4));
        return raw;
    }

    private static byte[] RawAttribute(MessageAttributeType type, byte[] value) => RawAttribute(BinaryPrimitives.ReverseEndianness((ushort)type), value);

    private static byte[] LongTermKey(byte[] username, byte[] realm, byte[] password, bool sha256)
    {
        var key = new byte[sha256 ? 32 : 16];
        MessageExtensions.DeriveLongTermKey(username, realm, password, sha256, key);
        return key;
    }

    private static byte[] Xor(byte[] address, byte[] transactionId)
    {
        var result = new byte[address.Length];
        for (var i = 0; i < address.Length; i++)
        {
            var mask = i < 4 ? MagicCookie[i] : transactionId[i - 4];
            result[i] = (byte)(address[i] ^ mask);
        }

        return result;
    }

    private static byte[] Change(byte flags) => [0, 0, 0, flags];

    private static byte[] PortValue(ushort port, ushort rest = 0)
    {
        var value = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(value, port);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), rest);
        return value;
    }

    private static byte[] Algorithm(ushort algorithm)
    {
        var value = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(value, algorithm);
        return value;
    }

    private static byte[] AddressValue(byte family, ushort port, byte[] address, byte reserved = 0)
    {
        var value = new byte[4 + address.Length];
        value[0] = reserved;
        value[1] = family;
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), port);
        address.CopyTo(value.AsSpan(4));
        return value;
    }

    private static int Pad(int length) => (length + 3) & ~3;

    private static void EncodeHex(ReadOnlySpan<byte> data, Span<byte> destination, bool upper)
    {
        const string Lower = "0123456789abcdef";
        const string Upper = "0123456789ABCDEF";
        var hex = upper ? Upper : Lower;
        for (var i = 0; i < data.Length; i++)
        {
            destination[i * 2] = (byte)hex[data[i] >> 4];
            destination[i * 2 + 1] = (byte)hex[data[i] & 0x0F];
        }
    }

    private static byte[] FromHex(ReadOnlySpan<byte> text)
    {
        var destination = new byte[text.Length / 2];
        for (var i = 0; i < destination.Length; i++)
            destination[i] = (byte)((HexValue(text[i * 2]) << 4) | HexValue(text[i * 2 + 1]));
        return destination;
    }

    private static int HexValue(byte value)
    {
        if (value is >= (byte)'0' and <= (byte)'9')
            return value - (byte)'0';
        if (value is >= (byte)'a' and <= (byte)'f')
            return value - (byte)'a' + 10;
        return value - (byte)'A' + 10;
    }

    private static Task<StunRequestResult> SendAsync(
        IStunRequestHandler service,
        ReadOnlyMemory<byte> request,
        byte[]? remote = null,
        ushort remotePort = RemotePort,
        byte[]? local = null,
        ushort localPort = LocalPort,
        byte[]? other = null,
        ushort otherPort = OtherPort)
    {
        return service.Invoke(request, remote ?? RemoteV4, remotePort, local ?? LocalV4, localPort, other ?? OtherV4, otherPort).AsTask();
    }

    private readonly record struct StunAttr(ushort Type, byte[] Value);

    private interface IStunRequestHandler
    {
        ValueTask<StunRequestResult> Invoke(
            ReadOnlyMemory<byte> request,
            ReadOnlyMemory<byte> remoteAddress,
            ushort remotePort,
            ReadOnlyMemory<byte> thisAddress,
            ushort thisPort,
            ReadOnlyMemory<byte> otherAddress,
            ushort otherPort);
    }

    private sealed class FakeStunService : StunServiceBase, IStunRequestHandler
    {
        public bool Authorize { get; init; }
        public byte[]? Realm { get; init; }
        public byte[]? Password { get; set; }
        public Func<ReadOnlyMemory<byte>, int, ReadOnlyMemory<byte>>? Lookup { get; set; }
        public int PasswordRequests { get; private set; }
        public List<byte[]> SeenUsers { get; } = [];

        protected override bool RequireAuthorized => Authorize;

        protected override ReadOnlyMemory<byte> AuthorizationRealm => Realm ?? default;

        protected override ValueTask<ReadOnlyMemory<byte>> GetPasswordAsync(ReadOnlyMemory<byte> username)
        {
            var call = PasswordRequests++;
            SeenUsers.Add(username.ToArray());
            if (Lookup is not null)
                return new(Lookup(username, call));
            return new(Password ?? ReadOnlyMemory<byte>.Empty);
        }

        public ValueTask<StunRequestResult> Invoke(
            ReadOnlyMemory<byte> request,
            ReadOnlyMemory<byte> remoteAddress,
            ushort remotePort,
            ReadOnlyMemory<byte> thisAddress,
            ushort thisPort,
            ReadOnlyMemory<byte> otherAddress,
            ushort otherPort)
            => HandleRequestAsync(request, remoteAddress, remotePort, thisAddress, thisPort, otherAddress, otherPort);
    }

    private sealed class ThrowingAuthService : StunServiceBase, IStunRequestHandler
    {
        public byte[]? Realm { get; init; }

        protected override bool RequireAuthorized => true;

        protected override ReadOnlyMemory<byte> AuthorizationRealm => Realm ?? default;

        public ValueTask<StunRequestResult> Invoke(
            ReadOnlyMemory<byte> request,
            ReadOnlyMemory<byte> remoteAddress,
            ushort remotePort,
            ReadOnlyMemory<byte> thisAddress,
            ushort thisPort,
            ReadOnlyMemory<byte> otherAddress,
            ushort otherPort)
            => HandleRequestAsync(request, remoteAddress, remotePort, thisAddress, thisPort, otherAddress, otherPort);
    }

    private sealed class RequestBuilder
    {
        private readonly bool _rfc5389;
        private readonly byte[] _transactionId;
        private readonly byte[] _classicPrefix;
        private readonly List<(ushort Wire, byte[] Value)> _attributes = [];
        private byte[] _trailing = [];
        private MessageType _type = MessageType.Request;
        private ushort? _wireType;
        private ushort? _lengthOverride;

        public RequestBuilder(bool rfc5389 = true, byte[]? transactionId = null, byte[]? classicPrefix = null)
        {
            _rfc5389 = rfc5389;
            _transactionId = transactionId ?? TxId;
            _classicPrefix = classicPrefix ?? [0x11, 0x22, 0x33, 0x44];
        }

        public RequestBuilder Type(MessageType type)
        {
            _type = type;
            return this;
        }

        public RequestBuilder WireType(ushort wire)
        {
            _wireType = wire;
            return this;
        }

        public RequestBuilder Length(ushort length)
        {
            _lengthOverride = length;
            return this;
        }

        public RequestBuilder Add(MessageAttributeType type, byte[] value) => AddRaw(BinaryPrimitives.ReverseEndianness((ushort)type), value);

        public RequestBuilder AddRaw(ushort wire, byte[] value)
        {
            _attributes.Add((wire, value));
            return this;
        }

        public RequestBuilder Trailing(byte[] bytes)
        {
            _trailing = bytes;
            return this;
        }

        public byte[] Build()
        {
            var size = 20 + _trailing.Length;
            foreach (var attribute in _attributes)
                size += 4 + Pad(attribute.Value.Length);
            var buffer = new byte[size];
            if (_wireType is ushort wire)
                BinaryPrimitives.WriteUInt16BigEndian(buffer, wire);
            else
                BinaryPrimitives.WriteUInt16LittleEndian(buffer, (ushort)_type);
            _classicPrefix.CopyTo(buffer, 4);
            if (_rfc5389)
                MagicCookie.CopyTo(buffer, 4);
            _transactionId.CopyTo(buffer, 8);
            var offset = 20;
            foreach (var attribute in _attributes)
            {
                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset), attribute.Wire);
                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset + 2), (ushort)attribute.Value.Length);
                attribute.Value.CopyTo(buffer.AsSpan(offset + 4));
                offset += 4 + Pad(attribute.Value.Length);
            }

            _trailing.CopyTo(buffer, offset);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), _lengthOverride ?? (ushort)(buffer.Length - 20));
            return buffer;
        }
    }
}
