type LinkLayerType* = enum
    ## The Link layer type as described here: http://www.tcpdump.org/linktypes.html
    NULL = (0, "NULL"),
    ETHERNET = (1, "ETHERNET"),
    AX25 = (3, "AX25"),
    IEEE802_5 = (6, "IEEE802_5"),
    ARCNET_BSD = (7, "ARCNET_BSD"),
    SLIP = (8, "SLIP"),
    PPP = (9, "PPP"),
    FDDI = (10, "FDDI"),
    PPP_HDLC = (50, "PPP_HDLC"),
    PPP_ETHER = (51, "PPP_ETHER"),
    ATM_RFC1483 = (100, "ATM_RFC1483"),
    RAW = (101, "RAW"),
    C_HDLC = (104, "C_HDLC"),
    IEEE802_11 = (105, "IEEE802_11"),
    FRELAY = (107, "FRELAY"),
    LOOP = (108, "LOOP"),
    LINUX_SLL = (113, "LINUX_SLL"),
    LTALK = (114, "LTALK"),
    PFLOG = (117, "PFLOG"),
    IEEE802_11_PRISM = (119, "IEEE802_11_PRISM"),
    IP_OVER_FC = (122, "IP_OVER_FC"),
    SUNATM = (123, "SUNATM"),
    IEEE802_11_RADIOTAP = (127, "IEEE802_11_RADIOTAP"),
    ARCNET_LINUX = (129, "ARCNET_LINUX"),
    APPLE_IP_OVER_IEEE1394 = (138, "APPLE_IP_OVER_IEEE1394"),
    MTP2_WITH_PHDR = (139, "MTP2_WITH_PHDR"),
    MTP2 = (140, "MTP2"),
    MTP3 = (141, "MTP3"),
    SCCP = (142, "SCCP"),
    DOCSIS = (143, "DOCSIS"),
    LINUX_IRDA = (144, "LINUX_IRDA"),
    USER0 = (147, "USER0"),
    USER1 = (148, "USER1"),
    USER2 = (149, "USER2"),
    USER3 = (150, "USER3"),
    USER4 = (151, "USER4"),
    USER5 = (152, "USER5"),
    USER6 = (153, "USER6"),
    USER7 = (154, "USER7"),
    USER8 = (155, "USER8"),
    USER9 = (156, "USER9"),
    USER10 = (157, "USER10"),
    USER11 = (158, "USER11"),
    USER12 = (159, "USER12"),
    USER13 = (160, "USER13"),
    USER14 = (161, "USER14"),
    USER15 = (162, "USER15"),
    IEEE802_11_AVS = (163, "IEEE802_11_AVS"),
    BACNET_MS_TP = (165, "BACNET_MS_TP"),
    PPP_PPPD = (166, "PPP_PPPD"),
    GPRS_LLC = (169, "GPRS_LLC"),
    GPF_T = (170, "GPF_T"),
    GPF_F = (171, "GPF_F"),
    LINUX_LAPD = (177, "LINUX_LAPD"),
    BLUETOOTH_HCI_H4 = (187, "BLUETOOTH_HCI_H4"),
    USB_LINUX = (189, "USB_LINUX"),
    PPI = (192, "PPI"),
    IEEE802_15_4 = (195, "IEEE802_15_4"),
    SITA = (196, "SITA"),
    ERF = (197, "ERF"),
    BLUETOOTH_HCI_H4_WITH_PHDR = (201, "BLUETOOTH_HCI_H4_WITH_PHDR"),
    AX25_KISS = (202, "AX25_KISS"),
    LAPD = (203, "LAPD"),
    PPP_WITH_DIR = (204, "PPP_WITH_DIR"),
    C_HDLC_WITH_DIR = (205, "C_HDLC_WITH_DIR"),
    FRELAY_WITH_DIR = (206, "FRELAY_WITH_DIR"),
    IPMB_LINUX = (209, "IPMB_LINUX"),
    IEEE802_15_4_NONASK_PHY = (215, "IEEE802_15_4_NONASK_PHY"),
    USB_LINUX_MMAPPED = (220, "USB_LINUX_MMAPPED"),
    FC_2 = (224, "FC_2"),
    FC_2_WITH_FRAME_DELIMS = (225, "FC_2_WITH_FRAME_DELIMS"),
    IPNET = (226, "IPNET"),
    CAN_SOCKETCAN = (227, "CAN_SOCKETCAN"),
    IPV4 = (228, "IPV4"),
    IPV6 = (229, "IPV6"),
    IEEE802_15_4_NOFCS = (230, "IEEE802_15_4_NOFCS"),
    DBUS = (231, "DBUS"),
    DVB_CI = (235, "DVB_CI"),
    MUX27010 = (236, "MUX27010"),
    STANAG_5066_D_PDU = (237, "STANAG_5066_D_PDU"),
    NFLOG = (239, "NFLOG"),
    NETANALYZER = (240, "NETANALYZER"),
    NETANALYZER_TRANSPARENT = (241, "NETANALYZER_TRANSPARENT"),
    IPOIB = (242, "IPOIB"),
    MPEG_2_TS = (243, "MPEG_2_TS"),
    NG40 = (244, "NG40"),
    NFC_LLCP = (245, "NFC_LLCP"),
    INFINIBAND = (247, "INFINIBAND"),
    SCTP = (248, "SCTP"),
    USBPCAP = (249, "USBPCAP"),
    RTAC_SERIAL = (250, "RTAC_SERIAL"),
    BLUETOOTH_LE_LL = (251, "BLUETOOTH_LE_LL"),
    NETLINK = (253, "NETLINK"),
    BLUETOOTH_LINUX_MONITOR = (254, "BLUETOOTH_LINUX_MONITOR"),
    BLUETOOTH_BREDR_BB = (255, "BLUETOOTH_BREDR_BB"),
    BLUETOOTH_LE_LL_WITH_PHDR = (256, "BLUETOOTH_LE_LL_WITH_PHDR"),
    PROFIBUS_DL = (257, "PROFIBUS_DL"),
    PKTAP = (258, "PKTAP"),
    EPON = (259, "EPON"),
    IPMI_HPM_2 = (260, "IPMI_HPM_2"),
    ZWAVE_R1_R2 = (261, "ZWAVE_R1_R2"),
    ZWAVE_R3 = (262, "ZWAVE_R3"),
    WATTSTOPPER_DLM = (263, "WATTSTOPPER_DLM"),
    ISO_14443 = (264, "ISO_14443"),
    RDS = (265, "RDS"),
    USB_DARWIN = (266, "USB_DARWIN"),
    SDLC = (268, "SDLC")