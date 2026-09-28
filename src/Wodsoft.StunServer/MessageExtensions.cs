using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.StunServer
{
    public static class MessageExtensions
    {
        public static bool IsValid(this MessageType messageType)
        {
            return Enum.IsDefined(messageType);
        }

        public static bool IsValid(this MessageAttributeType attributeType)
        {
            return Enum.IsDefined(attributeType);
        }

        public static bool ValidateMessageIntegrity(this Span<byte> data)
        {
            using (var hmac = new HMACSHA1())
            {
                var hash = hmac.ComputeHash(data.Slice(0, data.Length - 28).ToArray());
                return hash.AsSpan().SequenceEqual(data.Slice(data.Length - 20, 20));
            }
        }

        public static void SetMessageIntegrity(this Span<byte> data)
        {
            using (var hmac = new HMACSHA1())
            {
                var hash = hmac.ComputeHash(data.Slice(0, data.Length - 28).ToArray());
                hash.AsSpan().CopyTo(data.Slice(data.Length - 20, 20));
            }
        }
    }
}
