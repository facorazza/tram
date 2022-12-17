import std/logging
import std/strformat
import std/strutils

import ../utils

type Tcp* = ref object
    sourcePort*: uint16
    destinationPort*: uint16
    sequenceNumber*: uint32
    acknowledgmentNumber*: uint32
    dataOffset*: uint8
    ns*: bool
    cwr*: bool
    ece*: bool
    erg*: bool
    ack*: bool
    psh*: bool
    rst*: bool
    syn*: bool
    fin*: bool
    windowSize*: uint16
    checksum*: uint16
    urgentPointer*: uint16
    #options*: uint16
    payload*: seq[uint8]

proc parseTcp*(data: seq[uint8]): Tcp =
    new result

    result.sourcePort = cast[uint16](data[0]) shl 8 + data[1]
    debug(fmt"Source port: {result.sourcePort}")

    result.destinationPort = cast[uint16](data[2]) shl 8 + data[3]
    debug(fmt"Destination port: {result.destinationPort}")

    result.sequenceNumber = ((cast[uint32](data[4]) shl 8 + cast[uint32](data[5])) shl 8 + cast[uint32](data[6])) shl 8 + data[7]
    debug(fmt"Sequence number: {result.sequenceNumber}")

    result.acknowledgmentNumber = ((
        cast[uint32](data[8]) shl 8 + cast[uint32](data[9])) shl 8 +
        cast[uint32](data[10])) shl 8 +
        data[11]
    debug(fmt"Acknowledgment number: {result.acknowledgmentNumber}")

    result.dataOffset = data[12] shr 4
    debug(fmt"Data offset: {result.dataOffset}")

    result.ns = cast[bool](data[12] and 0b00000_0001)
    result.cwr = cast[bool](data[13] and 0b1000_0000)
    result.ece = cast[bool](data[13] and 0b0100_0000)
    result.erg = cast[bool](data[13] and 0b0010_0000)
    result.ack = cast[bool](data[13] and 0b0001_0000)
    result.psh = cast[bool](data[13] and 0b0000_1000)
    result.rst = cast[bool](data[13] and 0b0000_0100)
    result.syn = cast[bool](data[13] and 0b0000_0010)
    result.fin = cast[bool](data[13] and 0b0000_0001)

    result.windowSize = cast[uint16](data[14]) shl 8 + data[15]
    debug(fmt"Window size: {result.windowSize}")

    result.checksum = cast[uint16](data[16]) shl 8 + data[17]
    debug(fmt"Checksum: 0x{toHex(result.checksum)}")

    result.urgentPointer = cast[uint16](data[18]) shl 8 + data[19]
    debug(fmt"Urgent pointer: {result.urgentPointer}")

    #result.options = data[20..result.internetHeaderLength * 4]
    #debug(fmt"Options: {result.options}")

    result.payload = data[result.dataOffset * 4 .. ^1]
    debug(fmt"Payload: {dataString(result.payload)}")
