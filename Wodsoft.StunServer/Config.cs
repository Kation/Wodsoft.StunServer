using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Wodsoft.StunServer
{
    public class Config
    {
        public string? PrimaryIPv4Address { get; set; }

        public string? PrimaryIPv6Address { get; set; }

        public string? SecondaryIPv4Address { get; set; }

        public string? SecondaryIPv6Address { get; set; }

        public int PrimaryPort { get; set; } = 3478;

        public int SecondaryPort { get; set; } = 3479;

        public int TLSPrimaryPort { get; set; } = 5349;

        public int TLSSecondaryPort { get; set; } = 5350;

        public string? LocalPrimaryIPv4Address { get; set; }

        public string? LocalPrimaryIPv6Address { get; set; }

        public string? LocalSecondaryIPv4Address { get; set; }

        public string? LocalSecondaryIPv6Address { get; set; }

        public int? LocalPrimaryPort { get; set; }

        public int? LocalSecondaryPort { get; set; }

        public int? LocalTLSPrimaryPort { get; set; }

        public int? LocalTLSSecondaryPort { get; set; }
        
        public bool EnableUDP { get; set; } = true;

        public bool EnableTCP { get; set; } = true;

        public bool EnableTLS { get; set; } = false;

        public bool EnableIPv4 { get; set; } = true;

        public bool EnableIPv6 { get; set; } = false;

        public string? CertificateFile { get; set; } = "tls.pem";

        public bool Validate()
        {
            if (!EnableIPv4 && !EnableIPv6)
            {
                Console.WriteLine("At least enable an IPv4 or IPv6.");
                return false;
            }
            if (EnableIPv4)
            {
                if (PrimaryIPv4Address == null)
                {
                    Console.WriteLine("PrimaryIPv4Address can't be null.");
                    return false;
                }
                if (SecondaryIPv4Address == null)
                {
                    Console.WriteLine("SecondaryIPv4Address can't be null.");
                    return false;
                }
                if (!IPAddress.TryParse(PrimaryIPv4Address, out var primaryIPv4Address))
                {
                    Console.WriteLine("PrimaryIPv4Address is invalid.");
                    return false;
                }
                if (primaryIPv4Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Console.WriteLine("PrimaryIPv4Address is not an IPv4 address.");
                    return false;
                }
                if (!IPAddress.TryParse(SecondaryIPv4Address, out var secondaryIPv4Address))
                {
                    Console.WriteLine("SecondaryIPv4Address is invalid.");
                    return false;
                }
                if (secondaryIPv4Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    Console.WriteLine("SecondaryIPv4Address is not an IPv4 address.");
                    return false;
                }
                if (LocalPrimaryIPv4Address != null)
                {
                    if (!IPAddress.TryParse(LocalPrimaryIPv4Address, out var localPrimaryIPv4Address))
                    {
                        Console.WriteLine("LocalPrimaryIPv4Address is invalid.");
                        return false;
                    }
                    if (localPrimaryIPv4Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        Console.WriteLine("LocalPrimaryIPv4Address is not an IPv4 address.");
                        return false;
                    }
                }
                if (LocalSecondaryIPv4Address != null)
                {
                    if (!IPAddress.TryParse(LocalSecondaryIPv4Address, out var localSecondaryIPv4Address))
                    {
                        Console.WriteLine("LocalSecondaryIPv4Address is invalid.");
                        return false;
                    }
                    if (localSecondaryIPv4Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        Console.WriteLine("LocalSecondaryIPv4Address is not an IPv4 address.");
                        return false;
                    }
                }
            }
            if (EnableIPv6)
            {
                if (PrimaryIPv6Address == null)
                {
                    Console.WriteLine("PrimaryIPv6Address can't be null.");
                    return false;
                }
                if (SecondaryIPv6Address == null)
                {
                    Console.WriteLine("SecondaryIPv6Address can't be null.");
                    return false;
                }
                if (!IPAddress.TryParse(PrimaryIPv6Address, out var primaryIPv6Address))
                {
                    Console.WriteLine("PrimaryIPv6Address is invalid.");
                    return false;
                }
                if (primaryIPv6Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    Console.WriteLine("PrimaryIPv6Address is not an IPv6 address.");
                    return false;
                }
                if (!IPAddress.TryParse(SecondaryIPv6Address, out var secondaryIPv6Address))
                {
                    Console.WriteLine("SecondaryIPv6Address is invalid.");
                    return false;
                }
                if (secondaryIPv6Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    Console.WriteLine("SecondaryIPv6Address is not an IPv6 address.");
                    return false;
                }
                if (LocalPrimaryIPv6Address != null)
                {
                    if (!IPAddress.TryParse(LocalPrimaryIPv6Address, out var localPrimaryIPv6Address))
                    {
                        Console.WriteLine("LocalPrimaryIPv6Address is invalid.");
                        return false;
                    }
                    if (localPrimaryIPv6Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        Console.WriteLine("LocalPrimaryIPv6Address is not an IPv6 address.");
                        return false;
                    }
                }
                if (LocalSecondaryIPv6Address != null)
                {
                    if (!IPAddress.TryParse(LocalSecondaryIPv6Address, out var localSecondaryIPv6Address))
                    {
                        Console.WriteLine("LocalSecondaryIPv6Address is invalid.");
                        return false;
                    }
                    if (localSecondaryIPv6Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        Console.WriteLine("LocalSecondaryIPv6Address is not an IPv6 address.");
                        return false;
                    }
                }
            }
            if (PrimaryPort <= 0)
            {
                Console.WriteLine("PrimaryPort can't less or equal than 0,");
                return false;
            }
            if (SecondaryPort <= 0)
            {
                Console.WriteLine("SecondaryPort can't less or equal than 0,");
                return false;
            }
            if (TLSPrimaryPort <= 0)
            {
                Console.WriteLine("TLSPrimaryPort can't less or equal than 0,");
                return false;
            }
            if (TLSSecondaryPort <= 0)
            {
                Console.WriteLine("TLSSecondaryPort can't less or equal than 0,");
                return false;
            }
            if (PrimaryPort > 65535)
            {
                Console.WriteLine("PrimaryPort can't larger than 65535,");
                return false;
            }
            if (SecondaryPort > 65535)
            {
                Console.WriteLine("SecondaryPort can't larger than 65535,");
                return false;
            }
            if (TLSPrimaryPort > 65535)
            {
                Console.WriteLine("TLSPrimaryPort can't larger than 65535,");
                return false;
            }
            if (TLSSecondaryPort > 65535)
            {
                Console.WriteLine("TLSSecondaryPort can't larger than 65535,");
                return false;
            }
            if (LocalPrimaryPort.HasValue)
            {
                if (LocalPrimaryPort <= 0)
                {
                    Console.WriteLine("LocalPrimaryPort can't less or equal than 0,");
                    return false;
                }
                if (LocalPrimaryPort > 65535)
                {
                    Console.WriteLine("LocalPrimaryPort can't larger than 65535,");
                    return false;
                }
            }
            if (LocalSecondaryPort.HasValue)
            {
                if (LocalSecondaryPort <= 0)
                {
                    Console.WriteLine("LocalSecondaryPort can't less or equal than 0,");
                    return false;
                }
                if (LocalSecondaryPort > 65535)
                {
                    Console.WriteLine("LocalSecondaryPort can't larger than 65535,");
                    return false;
                }
            }
            if (LocalTLSPrimaryPort.HasValue)
            {
                if (LocalTLSPrimaryPort <= 0)
                {
                    Console.WriteLine("LocalTLSPrimaryPort can't less or equal than 0,");
                    return false;
                }
                if (LocalTLSPrimaryPort > 65535)
                {
                    Console.WriteLine("LocalTLSPrimaryPort can't larger than 65535,");
                    return false;
                }
            }
            if (LocalTLSSecondaryPort.HasValue)
            {
                if (LocalTLSSecondaryPort <= 0)
                {
                    Console.WriteLine("LocalTLSSecondaryPort can't less or equal than 0,");
                    return false;
                }
                if (LocalTLSSecondaryPort > 65535)
                {
                    Console.WriteLine("LocalTLSSecondaryPort can't larger than 65535,");
                    return false;
                }
            }
            if (!EnableUDP && !EnableTCP && !EnableTLS)
            {
                Console.WriteLine("Must enable a UDP, TCP or TLS.");
                return false;
            }
            if (EnableTLS)
            {
                if (CertificateFile == null)
                {
                    Console.WriteLine("CertificateFile can't be null when TLS is enabled,");
                    return false;
                }
                if (!File.Exists(CertificateFile))
                {
                    Console.WriteLine("CertificateFile doesn't exists,");
                    return false;
                }
                X509Certificate2 certificate;
                try
                {
                    certificate = X509Certificate2.CreateFromPemFile(CertificateFile);
                }
                catch
                {
                    Console.WriteLine("CertificateFile is a invalid format pem certificate,");
                    return false;
                }
                if (!certificate.HasPrivateKey)
                {
                    Console.WriteLine("CertificateFile doesn't contains private key.");
                    return false;
                }
            }
            return true;
        }
    }
}
