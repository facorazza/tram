import std/logging
import std/sequtils
import std/strformat
import std/strtabs
import std/strutils

type Http* = ref object
    request*: string
    status*: string
    headers*: StringTableRef
    body*: string

proc parseHttp*(data: seq[uint8]): Http =
    new result

    var content = join(data.map(proc(x: uint8): char = x.chr)).splitLines()

    result.request = content[0]
    debug(fmt"Request: {result.request}")

    result.status = content[0]
    debug(fmt"Status: {result.status}")

    result.headers = newStringTable(mode=modeCaseSensitive)
    debug("Headers:")

    var i = 1
    for headerValuePair in content[1..^1]:
        i += 1
        if headerValuePair == "":
            break
        var pair = headerValuePair.split(": ", 2)
        result.headers[pair[0]] = pair[1]
        debug(indent(fmt"{pair[0]}: {pair[1]}", 2))

    result.body = join(content[i..^1], "\n\r")
    debug(fmt"Body: {result.body}")
