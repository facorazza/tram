import std/streams

proc newEIO*(msg: string): ref IOError =
  new result
  result.msg = msg

proc read*[T](s: Stream, result: var T) =
  if readData(s, addr(result), sizeof(T)) != sizeof(T):
    raise newEIO("Cannot read from stream")

const Printables = {' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'}

proc dataString*(data: openArray[uint8]): string =
    ## Procedure to get the data from a packet and print all the printables characters replacing the non-printable characters with dots
    result = ""
    var i = 0
    for c in data:
        if c.chr in Printables:
            result.add c.chr
        else:
            result.add "."
        i+=1
        if i > 15:
            result.add "\n"
        i = 0
