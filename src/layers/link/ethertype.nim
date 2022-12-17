type EtherType* = enum
    ## EtherTypes: https://en.wikipedia.org/wiki/EtherType
    IPv4 = (0x0800u16, "IPv4"),
    ARP = (0x0806u16, "ARP"),
    RARP = (0x8035u16, "RARP"),
    IPv6 = (0x86DDu16, "IPv6"),
    LLDP = (0x88CCu16, "LLDP"),
