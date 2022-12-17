import std/strformat
import std/strutils

type MacAddress* = (uint8, uint8, uint8, uint8, uint8, uint8)

proc parseMacAddress*(f: openArray[uint8]): MacAddress =
    return (f[0], f[1], f[2], f[3], f[4], f[5])

proc printMacAddress*(mac: MacAddress): string =
    return fmt"{toHex(mac[0])}:{toHex(mac[1])}:{toHex(mac[2])}:{toHex(mac[3])}:{toHex(mac[4])}:{toHex(mac[5])}"
