import std/logging
import std/strformat
import std/strutils

from ip_protocols import IpProtocols
from ../utils import toAscii

type Ipv4Address* = (uint8, uint8, uint8, uint8)

type Ipv4Packet* = ref object
    version*: uint8
    internetHeaderLength*: uint8
    differentiatedServiceCodePoint*: uint8
    explicitCongestionNotification*: uint8
    totalLength*: uint16
    identification*: uint16
    evilBit*: bool
    dontFragment*: bool
    moreFragments*: bool
    fragmentOffset*: uint16
    timeToLive*: uint8
    protocol*: IpProtocols
    headerChecksum*: uint16
    sourceIpAddress*: Ipv4Address
    destinationIpAddress*: Ipv4Address
    # options*:
    payload*: seq[uint8]

proc parseIpv4Version(f: uint8): uint8 =
    # The first header field in an IP packet is the four-bit version field. For IPv4, this is always
    # equal to 4.
    return f shr 4

proc parseIpv4InternetHeaderLength(f: uint8): uint8 =
    # The IPv4 header is variable in size due to the optional 14th field (options). The IHL field
    # contains the size of the IPv4 header; it has 4 bits that specify the number of 32-bit words in
    # the header. The minimum value for this field is 5,[35] which indicates a length of 5 × 32 bits
    # = 160 bits = 20 bytes. As a 4-bit field, the maximum value is 15; this means that the maximum
    # size of the IPv4 header is 15 × 32 bits = 480 bits = 60 bytes.
    return f shl 4 shr 4

proc parseIpv4DifferentiatedServiceCodePoint(f: uint8): uint8 =
    # Originally defined as the type of service (ToS), this field specifies differentiated services
    # (DiffServ) per RFC 2474.[a] Real-time data streaming makes use of the DSCP field. An example
    # is Voice over IP (VoIP), which is used for interactive voice services.
    return f shr 6

proc parseIpv4ExplicitCongestionNotification(f: uint8): uint8 =
    # This field is defined in RFC 3168 and allows end-to-end notification of network congestion
    # without dropping packets. ECN is an optional feature available when both endpoints support it
    # and effective when also supported by the underlying network.
    return f shl 6 shr 6

proc parseIpv4Address*(ip: openArray[uint8]): Ipv4Address =
    return (ip[0], ip[1], ip[2], ip[3])

proc printIpv4Address*(ip: Ipv4Address): string =
    return fmt"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}"

proc parseIpv4TotalLength(f: uint8, g: uint8): uint16 =
    # This 16-bit field defines the entire packet size in bytes, including header and data.
    return cast[uint16](f) shl 8 + g

proc parseIpv4Identification(f: uint8, g: uint8): uint16 =
    # This field is an identification field and is primarily used for uniquely identifying the group
    # of fragments of a single IP datagram.
    return cast[uint16](f) shl 8 + g

proc parseIpv4EvilBit(f: uint8): bool =
    # This bit is reserved and must be zero.
    return cast[bool](f and 0b10000_0000)

proc parseIpv4DontFragmentBit(f: uint8): bool =
    # If the DF flag is set, and fragmentation is required to route the packet, then the packet is
    # dropped. This can be used when sending packets to a host that does not have resources to
    # perform reassembly of fragments. It can also be used for path MTU discovery, either
    # automatically by the host IP software, or manually using diagnostic tools such as ping or
    # traceroute.
    return cast[bool](f and 0b01000_0000)

proc parseIpv4MoreFragmentsBit(f: uint8): bool =
    # For unfragmented packets, the MF flag is cleared. For fragmented packets, all fragments except the last have the MF flag set. The last fragment has a non-zero Fragment Offset field, differentiating it from an unfragmented packet.
    return cast[bool](f and 0b00100_0000)

proc parseIpv4FragmentOffset(f: uint8, g: uint8): uint16 =
    # This field specifies the offset of a particular fragment relative to the beginning of the
    # original unfragmented IP datagram. The fragmentation offset value for the first fragment is
    # always 0. The field is 13 bits wide, so that the offset can be from 0 to 8191.
    # Fragments are specified in units of 8 bytes, which is why fragment length must be a multiple of 8.
    return cast[uint16](f) shl 5 + g

proc parseIpv4TimeToLive(f: uint8): uint8 =
    # An eight-bit time to live field limits a datagram's lifetime to prevent network failure in the
    # event of a routing loop. It is specified in seconds, but time intervals less than 1 second are
    # rounded up to 1. In practice, the field is used as a hop count—when the datagram arrives at a
    # router, the router decrements the TTL field by one. When the TTL field hits zero, the router
    # discards the packet and typically sends an ICMP time exceeded message to the sender.
    return f

proc parseIpProtocol(f: uint8): IpProtocols =
    # This field defines the protocol used in the data portion of the IP datagram.
    return IpProtocols(f)

proc parseIpv4HeaderChecksum(f: uint8, g: uint8): uint16 =
    # The 16-bit IPv4 header checksum field is used for error-checking of the header. When a packet
    # arrives at a router, the router calculates the checksum of the header and compares it to the
    # checksum field. If the values do not match, the router discards the packet. Errors in the data
    # field must be handled by the encapsulated protocol. Both UDP and TCP have separate checksums
    # that apply to their data.
    # When a packet arrives at a router, the router decreases the TTL field in the header.
    # Consequently, the router must calculate a new header checksum.
    # The checksum field is the 16 bit one's complement of the one's complement sum of all 16 bit
    # words in the header. For purposes of computing the checksum, the value of the checksum field
    # is zero.
    return cast[uint16](f) shl 8 + g

proc parseIpv4*(data: seq[uint8]): Ipv4Packet =
    new result

    result.version = parseIpv4Version(data[0])
    debug(fmt"Version: {result.version}")

    result.internetHeaderLength = parseIpv4InternetHeaderLength(data[0])
    debug(fmt"Internet header length: {result.internetHeaderLength} ({result.internetHeaderLength * 4} bytes)")

    result.differentiatedServiceCodePoint = parseIpv4DifferentiatedServiceCodePoint(data[1])
    debug(fmt"Differentiated service code point: {result.differentiatedServiceCodePoint}")

    result.explicitCongestionNotification = parseIpv4ExplicitCongestionNotification(data[1])
    debug(fmt"Explicit congestion notification: {result.explicitCongestionNotification}")

    result.totalLength = parseIpv4TotalLength(data[2], data[3])
    debug(fmt"Total length: {result.totalLength}")

    result.identification = parseIpv4Identification(data[4], data[5])
    debug(fmt"Identification: {result.identification}")

    result.evilBit = parseIpv4EvilBit(data[6])
    debug(fmt"Evil bit: {result.evilBit}")

    result.dontFragment = parseIpv4DontFragmentBit(data[6])
    debug(fmt"Evil bit: {result.evilBit}")

    result.moreFragments = parseIpv4MoreFragmentsBit(data[6])
    debug(fmt"Evil bit: {result.evilBit}")

    result.fragmentOffset = parseIpv4FragmentOffset(data[6], data[7])
    debug(fmt"Fragment offset: {result.fragmentOffset}")

    result.timeToLive = parseIpv4TimeToLive(data[8])
    debug(fmt"Time to live: {result.timeToLive}")

    result.protocol = parseIpProtocol(data[9])
    debug(fmt"Protocol: {result.protocol}")

    result.headerChecksum = parseIpv4HeaderChecksum(data[10], data[11])
    debug(fmt"Header checksum: 0x{result.headerChecksum.toHex()}")

    result.sourceIpAddress = parseIpv4Address(data[12..15])
    debug(fmt"Source IP: {printIpv4Address(result.sourceIpAddress)}")

    result.destinationIpAddress = parseIpv4Address(data[16..19])
    debug(fmt"Destination IP: {printIpv4Address(result.destinationIpAddress)}")

    #result.options = data[20..result.internetHeaderLength * 4]
    #debug(fmt"Options: {result.options}")

    if result.internetHeaderLength - 5 > 0:
        echo "ihl > 5 !!!"

    result.payload = data[result.internetHeaderLength * 4 .. ^1]
    debug(fmt"Payload: {result.payload.toAscii()}")
