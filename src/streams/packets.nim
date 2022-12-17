import std/endians
import std/logging
import std/streams

import global_header
import link_layer_types
import ../layers/link/ethernet

type RecordHeader* = ref object
    tsSec*: uint32
    tsUsec*: uint32
    inclLen*: uint32
    origLen*: uint32

type Packet* = ref object
    header*: RecordHeader
    data*: seq[uint8]
    ethernetFrame*: EthernetFrame

type PacketStream* = ref object
    stream*: FileStream
    globalHeader*: GlobalHeader

proc initPacketStream*(filename: string): PacketStream =
    new result

    result.stream = newFileStream(filename, fmRead)
    result.globalHeader = result.stream.readGlobalHeader()

proc readPacketHeader(s: Stream, globalHeader: GlobalHeader): RecordHeader =
    new result

    result.tsSec = s.readUint32()
    result.tsUsec = s.readUint32()
    result.inclLen = s.readUint32()
    result.origLen = s.readUint32()

    if not globalHeader.swapped:
        bigEndian32(result.tsSec.addr, result.tsSec.addr)
        bigEndian32(result.tsUsec.addr, result.tsUsec.addr)
        bigEndian32(result.inclLen.addr, result.inclLen.addr)
        bigEndian32(result.origLen.addr, result.origLen.addr)

proc readPacket(s: Stream, globalHeader: GlobalHeader): Packet =
    ## Reads the data for a record given the record header containing the length of the record and
    ## advanced the pointer to the next record header
    new result

    # Read packet header
    result.header = readPacketHeader(s, globalHeader)

    # Read packet data
    result.data.newSeq(result.header.inclLen)
    if not globalHeader.swapped:
        for i in countdown(result.header.inclLen.int - 1, 0):
            result.data[i] = s.readUint8()
    else:
        for i in 0 ..< result.header.inclLen.int:
            result.data[i] = s.readUint8()

iterator getPackets*(ps: PacketStream): Packet =
    var packet: Packet

    while not ps.stream.atEnd:
        try:
            packet = ps.stream.readPacket(ps.globalHeader)
        except IOError as e:
            error(e.msg)
            break

        if ps.globalHeader.network == LinkLayerType.ETHERNET:
            packet.ethernetFrame = initEthernetFrame(packet.data)

        yield packet
