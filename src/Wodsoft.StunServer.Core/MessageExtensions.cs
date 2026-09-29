using System;
using System.Collections.Generic;
using System.Linq;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
    }
}
