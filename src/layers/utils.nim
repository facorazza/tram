proc toAscii*(data: openArray[uint8]): string =
    ## Procedure to print all printables characters replacing the non-printable characters with dots
    result = ""
    for c in data:
        if c >= 32 and c < 127:
            result.add c.chr
        else:
            result.add "."
