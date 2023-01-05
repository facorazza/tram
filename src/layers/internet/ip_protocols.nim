type IpProtocols* = enum
    ICMP = (0x01u8, "ICMP"),
    IGMP = (0x02u8, "IGMP"),
    TCP = (0x06u8, "TCP"),
    UDP = (0x11u8, "UDP"),
    ENCAP = (029u8, "ENCAP"),
    OSPF = (0x59u8, "OSPF"),
    SCTP = (0x84u8, "SCTP")
