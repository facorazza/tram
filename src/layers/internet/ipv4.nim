import std/logging
import std/strformat
import std/strutils

import ../utils

type Ipv4Address* = (uint8, uint8, uint8, uint8)

type Ipv4Packet* = ref object
    version*: uint8
    internetHeaderLength*: uint8
    differentiatedServiceCodePoint*: uint8
    explicitCongestionNotification*: uint8
    totalLength*: uint16
    identification*: uint16
    flags*: uint8
    evilBit*: bool
    dontFragment*: bool
    moreFragments*: bool
    fragmentOffset*: uint8
    timeToLive*: uint8
    protocol*: uint16
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

    result.totalLength = cast[uint16](data[2]) shl 8 + data[3]
    debug(fmt"Total length: {result.totalLength}")

    result.identification = cast[uint16](data[4]) shl 8 + data[5]
    debug(fmt"Identification: {result.identification}")

    result.flags = data[6]
    #debug(fmt"Flags: {result.flags}")

    #result.fragmentOffset = data[6..7]
    #debug(fmt"Fragment offset: {result.fragmentOffset}")

    result.timeToLive = data[8]
    debug(fmt"Time to live: {result.timeToLive}")

    result.protocol = data[9]
    debug(fmt"Protocol: {result.protocol}")

    result.headerChecksum = cast[uint16](data[10]) shl 8 + data[11]
    debug(fmt"Header checksum: 0x{toHex(result.headerChecksum)}")

    result.sourceIpAddress = parseIpv4Address(data[12..15])
    debug(fmt"Source IP: {printIpv4Address(result.sourceIpAddress)}")

    result.destinationIpAddress = parseIpv4Address(data[16..19])
    debug(fmt"Destination IP: {printIpv4Address(result.destinationIpAddress)}")

    #result.options = data[20..result.internetHeaderLength * 4]
    #debug(fmt"Options: {result.options}")

    if result.internetHeaderLength - 5 > 0:
        echo "ihl > 5 !!!"

    result.payload = data[result.internetHeaderLength * 4 .. ^1]
    debug(fmt"Payload: {dataString(result.payload)}")