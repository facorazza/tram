import std/logging
import std/strformat

import ethertype

from mac import MacAddress, parseMacAddress, printMacAddress
from ../utils import toAscii

type EthernetFrame* = ref object
    destinationMacAddress*: MacAddress
    sourceMacAddress*: MacAddress
    etherType*: EtherType
    payload*: seq[uint8]

proc parseEtherType(f: openArray[uint8]): EtherType =
    return EtherType(cast[uint16](f[0]) shl 8 + f[1])

proc initEthernetFrame*(frame: seq[uint8]): EthernetFrame =
    new result

    result.destinationMacAddress = parseMacAddress(frame[0..5])
    debug(fmt"Destination MAC: {printMacAddress(result.destinationMacAddress)}")

    result.sourceMacAddress = parseMacAddress(frame[6..11])
    debug(fmt"Source MAC: {printMacAddress(result.sourceMacAddress)}")

    result.etherType = parseEtherType(frame[12..13])
    debug(fmt"EtherType: {result.etherType}")

    result.payload = frame[14..^1]
    debug(fmt"Payload: {toAscii(result.payload)}")
