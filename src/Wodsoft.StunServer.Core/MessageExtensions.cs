using System;
using System.Collections.Generic;
using System.Linq;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace Wodsoft.StunServer
{
    public static class MessageExtensions
    {
        public const ushort PasswordAlgorithmMd5 = 1;
        public const ushort PasswordAlgorithmSha256 = 2;

        public static bool IsValid(this MessageType messageType)
        {
            return Enum.IsDefined(messageType);
        }

        public static bool IsValid(this MessageAttributeType attributeType)
        {
            return Enum.IsDefined(attributeType);
        }

        public static bool VerifyMessageIntegrity(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, ReadOnlySpan<byte> hash)
        {
            if (hash.Length is not (20 or 32))
                return false;
            Span<byte> actual = stackalloc byte[32];
            var written = ComputeMessageIntegrity(message, key, hash.Length == 32, actual);
            return written == hash.Length && CryptographicOperations.FixedTimeEquals(actual.Slice(0, written), hash);
        }

        public static void WriteMessageIntegrity(Span<byte> message, int integrityOffset, ReadOnlySpan<byte> key, bool sha256)
        {
            var hashLength = sha256 ? 32 : 20;
            var attributeSize = hashLength + 4;
            BinaryPrimitives.WriteUInt16BigEndian(message.Slice(2), (ushort)(integrityOffset - 20 + attributeSize));
            MemoryMarshal.Write(message.Slice(integrityOffset), sha256 ? MessageAttributeType.MessageIntegritySHA256 : MessageAttributeType.MessageIntegrity);
            BinaryPrimitives.WriteUInt16BigEndian(message.Slice(integrityOffset + 2), (ushort)hashLength);
            Span<byte> hash = stackalloc byte[32];
            var written = ComputeMessageIntegrity(message.Slice(0, integrityOffset), key, sha256, hash);
            hash.Slice(0, written).CopyTo(message.Slice(integrityOffset + 4));
        }

        public static void DeriveLongTermKey(ReadOnlySpan<byte> username, ReadOnlySpan<byte> realm, ReadOnlySpan<byte> password, bool sha256, Span<byte> destination)
        {
            var algorithm = sha256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.MD5;
            using var hash = IncrementalHash.CreateHash(algorithm);
            hash.AppendData(username);
            hash.AppendData(":"u8);
            hash.AppendData(realm);
            hash.AppendData(":"u8);
            hash.AppendData(password);
            hash.GetHashAndReset(destination);
        }

        private static int ComputeMessageIntegrity(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, bool sha256, Span<byte> destination)
        {
            var algorithm = sha256 ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
            using var hmac = IncrementalHash.CreateHMAC(algorithm, key);
            hmac.AppendData(message);
            return hmac.GetHashAndReset(destination);
        }

        /// <summary>
        /// 将 <see cref="SocketAddress"/> 格式化为 <c>1.2.3.4:5060</c> 或 <c>[2001:db8::1]:5060</c>，
        /// 直接解析原始缓冲区，不构造 <see cref="IPAddress"/> / <see cref="IPEndPoint"/>，只分配结果字符串。
        /// </summary>
        public static string Format(this SocketAddress socketAddress)
        {
            ArgumentNullException.ThrowIfNull(socketAddress);
            Span<char> buffer = stackalloc char[MaxFormattedLength];
            if (!TryFormat(socketAddress, buffer, out var written))
            {
                // 非 IP 地址（例如 Unix 域套接字），退回系统实现。
                return socketAddress.ToString();
            }
            return new string(buffer.Slice(0, written));
        }

        /// <summary>
        /// 格式化不含端口的 IP 地址，<paramref name="address"/> 必须是 4 字节（IPv4）或 16 字节（IPv6），
        /// 字节按网络序排列。输出形如 <c>192.168.1.10</c> 或 <c>2001:db8::1</c>（IPv6 不带方括号）。
        /// </summary>
        public static string Format(byte[] address)
        {
            ArgumentNullException.ThrowIfNull(address);
            return Format(address.AsSpan());
        }

        /// <inheritdoc cref="Format(byte[])"/>
        public static string Format(ReadOnlySpan<byte> address)
        {
            Span<char> buffer = stackalloc char[MaxIPv6AddressLength];
            if (!TryFormatAddress(address, buffer, out int written))
                throw new ArgumentException("Address must be 4 (IPv4) or 16 (IPv6) bytes long.", nameof(address));
            return new string(buffer.Slice(0, written));
        }

        /// <summary>
        /// 将 <see cref="SocketAddress"/> 直接写入 <paramref name="destination"/> 并返回写入的字符数，零分配。
        /// <paramref name="destination"/> 至少需要 <see cref="GetMaxFormattedLength"/> 个字符（IPv4 21、IPv6 58）。
        /// </summary>
        /// <exception cref="ArgumentException">缓冲区不足，或地址不是 IPv4/IPv6。</exception>
        public static int Format(this SocketAddress socketAddress, Span<char> destination)
        {
            ArgumentNullException.ThrowIfNull(socketAddress);
            int required = GetMaxFormattedLength(socketAddress);
            if (required == 0)
                throw new ArgumentException("Socket address is not an IPv4/IPv6 address.", nameof(socketAddress));
            if (destination.Length < required)
                throw new ArgumentException($"Destination must be at least {required} characters long.", nameof(destination));

            if (!TryFormat(socketAddress, destination, out int written))
                throw new ArgumentException("Socket address is too small for its address family.", nameof(socketAddress));
            return written;
        }

        /// <summary>
        /// 将 IPv4/IPv6 地址（4 或 16 字节）直接写入 <paramref name="destination"/> 并返回写入的字符数，零分配。
        /// 输出形如 <c>192.168.1.10</c> 或 <c>2001:db8::1</c>（不带方括号与端口）。
        /// </summary>
        /// <exception cref="ArgumentException">缓冲区不足，或地址长度不是 4/16 字节。</exception>
        public static int Format(ReadOnlySpan<byte> address, Span<char> destination)
        {
            int required = address.Length switch
            {
                4 => MaxIPv4AddressLength,
                16 => MaxIPv6AddressLength,
                _ => 0
            };
            if (required == 0)
                throw new ArgumentException("Address must be 4 (IPv4) or 16 (IPv6) bytes long.", nameof(address));
            if (destination.Length < required)
                throw new ArgumentException($"Destination must be at least {required} characters long.", nameof(destination));

            TryFormatAddress(address, destination, out int written);
            return written;
        }

        /// <summary>
        /// 将 <see cref="SocketAddress"/> 写入目标缓冲区，<paramref name="destination"/> 至少需要
        /// <see cref="GetMaxFormattedLength"/> 给出的长度（IPv4 21、IPv6 58）。
        /// </summary>
        public static bool TryFormat(this SocketAddress socketAddress, Span<char> destination, out int charsWritten)
        {
            ArgumentNullException.ThrowIfNull(socketAddress);
            ReadOnlySpan<byte> source = socketAddress.Buffer.Span;
            int size = socketAddress.Size;
            if ((uint)size > (uint)source.Length)
            {
                charsWritten = 0;
                return false;
            }

            switch (socketAddress.Family)
            {
                case AddressFamily.InterNetwork:
                    if (size < IPv4SocketAddressSize || destination.Length < MaxIPv4FormattedLength)
                        break;
                    return TryFormatIPv4(source, destination, out charsWritten);

                case AddressFamily.InterNetworkV6:
                    if (size < IPv6SocketAddressSize || destination.Length < MaxFormattedLength)
                        break;
                    return TryFormatIPv6(source, destination, out charsWritten);
            }

            charsWritten = 0;
            return false;
        }

        /// <summary>格式化后的最大字符数（含端口与方括号）。</summary>
        public static int GetMaxFormattedLength(this SocketAddress socketAddress)
        {
            ArgumentNullException.ThrowIfNull(socketAddress);
            return socketAddress.Family switch
            {
                AddressFamily.InterNetwork => MaxIPv4FormattedLength,
                AddressFamily.InterNetworkV6 => MaxFormattedLength,
                _ => 0
            };
        }

        // "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535"
        private const int MaxFormattedLength = 58;

        // "255.255.255.255:65535"
        private const int MaxIPv4FormattedLength = 21;

        // "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        private const int MaxIPv6AddressLength = 39;

        // "255.255.255.255"
        private const int MaxIPv4AddressLength = 15;

        private const int IPv4SocketAddressSize = 16;
        private const int IPv6SocketAddressSize = 28;

        private static bool TryFormatAddress(ReadOnlySpan<byte> address, Span<char> destination, out int charsWritten)
        {
            switch (address.Length)
            {
                case 4:
                {
                    if (destination.Length < MaxIPv4AddressLength)
                        break;

                    int pos = 0;
                    WriteIPv4(address, destination, ref pos);
                    charsWritten = pos;
                    return true;
                }

                case 16:
                {
                    if (destination.Length < MaxIPv6AddressLength)
                        break;

                    Span<ushort> groups = stackalloc ushort[8];
                    ReadIPv6Groups(address, 0, groups);
                    charsWritten = WriteIPv6(groups, destination);
                    return true;
                }
            }

            charsWritten = 0;
            return false;
        }

        private static bool TryFormatIPv4(ReadOnlySpan<byte> source, Span<char> destination, out int charsWritten)
        {
            int pos = 0;
            WriteIPv4(source.Slice(4, 4), destination, ref pos);
            destination[pos++] = ':';
            WriteDecimal(destination, ref pos, ReadPort(source));
            charsWritten = pos;
            return true;
        }

        private static bool TryFormatIPv6(ReadOnlySpan<byte> source, Span<char> destination, out int charsWritten)
        {
            Span<ushort> groups = stackalloc ushort[8];
            ReadIPv6Groups(source, 8, groups);

            int pos = 0;
            destination[pos++] = '[';
            pos += WriteIPv6(groups, destination.Slice(pos));
            // 与内置 SocketAddress -> IPEndPoint 转换保持一致：只有 fe80::/10 保留 scope id。
            if ((groups[0] & 0xFFC0) == 0xFE80)
            {
                uint scopeId = BinaryPrimitives.ReadUInt32LittleEndian(source.Slice(24));
                if (scopeId != 0)
                {
                    destination[pos++] = '%';
                    WriteDecimal(destination, ref pos, scopeId);
                }
            }
            destination[pos++] = ']';
            destination[pos++] = ':';
            WriteDecimal(destination, ref pos, ReadPort(source));
            charsWritten = pos;
            return true;
        }

        private static int WriteIPv6(ReadOnlySpan<ushort> groups, Span<char> destination)
        {
            int pos = 0;
            if (ShouldEmbedIPv4(groups))
            {
                WriteSections(groups.Slice(0, 6), destination, ref pos);
                if (destination[pos - 1] != ':')
                    destination[pos++] = ':';
                WriteIPv4(groups[6], groups[7], destination, ref pos);
            }
            else
            {
                WriteSections(groups, destination, ref pos);
            }
            return pos;
        }

        // RFC 5952 4.2：把最长的一段 0 压缩为 "::"，长度至少为 2，等长时取靠前的一段。
        private static void WriteSections(ReadOnlySpan<ushort> groups, Span<char> destination, ref int pos)
        {
            (int zeroStart, int zeroEnd) = FindCompressionRange(groups);
            bool needsColon = false;

            if (zeroStart >= 0)
            {
                for (int i = 0; i < zeroStart; i++)
                {
                    if (needsColon)
                        destination[pos++] = ':';
                    needsColon = true;
                    WriteHex(groups[i], destination, ref pos);
                }

                destination[pos++] = ':';
                destination[pos++] = ':';
                needsColon = false;
            }

            for (int i = zeroEnd; i < groups.Length; i++)
            {
                if (needsColon)
                    destination[pos++] = ':';
                needsColon = true;
                WriteHex(groups[i], destination, ref pos);
            }
        }

        private static (int Start, int End) FindCompressionRange(ReadOnlySpan<ushort> groups)
        {
            int longestLength = 0, longestStart = -1, currentLength = 0;
            for (int i = 0; i < groups.Length; i++)
            {
                if (groups[i] == 0)
                {
                    currentLength++;
                    if (currentLength > longestLength)
                    {
                        longestLength = currentLength;
                        longestStart = i - currentLength + 1;
                    }
                }
                else
                {
                    currentLength = 0;
                }
            }

            return longestLength > 1 ? (longestStart, longestStart + longestLength) : (-1, 0);
        }

        // RFC 5952 5：IPv4 映射 / 兼容 / SIIT / ISATAP 地址按点分十进制输出末 32 位。
        private static bool ShouldEmbedIPv4(ReadOnlySpan<ushort> groups)
        {
            if (groups[0] == 0 && groups[1] == 0 && groups[2] == 0 && groups[3] == 0 && groups[6] != 0)
            {
                if (groups[4] == 0 && (groups[5] == 0 || groups[5] == 0xFFFF))
                    return true;
                if (groups[4] == 0xFFFF && groups[5] == 0)
                    return true;
            }

            return groups[4] == 0 && groups[5] == 0x5EFE;
        }

        private static void ReadIPv6Groups(ReadOnlySpan<byte> source, int offset, Span<ushort> groups)
        {
            for (int i = 0; i < groups.Length; i++)
                groups[i] = (ushort)((source[offset + i * 2] << 8) | source[offset + i * 2 + 1]);
        }

        private static void WriteIPv4(ReadOnlySpan<byte> address, Span<char> destination, ref int pos)
        {
            for (int i = 0; i < 4; i++)
            {
                if (i != 0)
                    destination[pos++] = '.';
                WriteDecimal(destination, ref pos, address[i]);
            }
        }

        private static void WriteIPv4(ushort high, ushort low, Span<char> destination, ref int pos)
        {
            WriteDecimal(destination, ref pos, (byte)(high >> 8));
            destination[pos++] = '.';
            WriteDecimal(destination, ref pos, (byte)high);
            destination[pos++] = '.';
            WriteDecimal(destination, ref pos, (byte)(low >> 8));
            destination[pos++] = '.';
            WriteDecimal(destination, ref pos, (byte)low);
        }

        private static void WriteHex(ushort value, Span<char> destination, ref int pos)
        {
            int shift = value switch
            {
                < 0x10 => 0,
                < 0x100 => 4,
                < 0x1000 => 8,
                _ => 12
            };

            for (; shift >= 0; shift -= 4)
                destination[pos++] = HexChar((value >> shift) & 0xF);
        }

        private static void WriteDecimal(Span<char> destination, ref int pos, uint value)
        {
            Span<char> digits = stackalloc char[10];
            int count = 0;
            do
            {
                digits[count++] = (char)('0' + (int)(value % 10));
                value /= 10;
            }
            while (value != 0);

            while (count > 0)
                destination[pos++] = digits[--count];
        }

        private static char HexChar(int value) => (char)(value < 10 ? '0' + value : 'a' + (value - 10));

        private static ushort ReadPort(ReadOnlySpan<byte> source) => (ushort)((source[2] << 8) | source[3]);
    }
}
