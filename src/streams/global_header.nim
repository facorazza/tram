import std/endians
import std/strformat
import std/streams
import std/strutils

from link_layer_types import LinkLayerType

type GlobalHeader* = ref object
    ## This header starts the libpcap file and will be followed by the first packet header
    magicNumber*: uint32
    nanos*: bool
    swapped*: bool
    versionMajor*: uint16
    versionMinor*: uint16
    thiszone*: int32
    sigfigs*: uint32
    snaplen*: uint32
    network*: LinkLayerType

proc `$`*(header: GlobalHeader): string =
    ## Procedure to get the header as a nicely formatted string
    fmt"""Global header:
    Magic number: 0x{header.magicNumber.toHex}
        Byte order: {(if header.swapped: "little" else: "big")} endian
        Resolution: {(if header.nanos: "nanosecond" else: "millisecond")}
    Version: {header.versionMajor}.{header.versionMinor}
    GMT Offset (s): {header.thiszone}
    Timestamp accuracy: {header.sigfigs}
    Max snapshot length: {header.snaplen}
    Network: {header.network}"""

proc readGlobalHeader*(s: Stream): GlobalHeader =
    ## Reads the header from the start of the stream and advanced the pointer to the first record header
    new result
    result.magicNumber = s.readUint32()
    case result.magicNumber:
    of 0xA1B2C3D4.uint32:
        result.swapped = true
        result.nanos = false
    of 0xD4C3B2A1.uint32:
        result.swapped = false
        result.nanos = false
    of 0xA1B23C4D.uint32:
        result.swapped = true
        result.nanos = true
    of 0x4D3CB2A1.uint32:
        result.swapped = false
        result.nanos = true
    else:
        raise new ValueError

    result.versionMajor = s.readUint16()
    result.versionMinor = s.readUint16()
    result.thiszone = s.readInt32()
    result.sigfigs = s.readUint32()
    result.snaplen = s.readUint32()
    var network = s.readUint32()

    if not result.swapped:
        bigEndian32(result.magicNumber.addr, result.magicNumber.addr)
        bigEndian16(result.versionMajor.addr, result.versionMajor.addr)
        bigEndian16(result.versionMinor.addr, result.versionMinor.addr)
        bigEndian32(result.thiszone.addr, result.thiszone.addr)
        bigEndian32(result.sigfigs.addr, result.sigfigs.addr)
        bigEndian32(result.snaplen.addr, result.snaplen.addr)
        bigEndian32(network.addr, network.addr)
    
    result.network = LinkLayerType(network)
