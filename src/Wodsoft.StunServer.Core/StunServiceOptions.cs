using System;
using System.Collections.Generic;
using System.Text;

namespace Wodsoft.StunServer
{
    public class StunServiceOptions
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
    }
}
