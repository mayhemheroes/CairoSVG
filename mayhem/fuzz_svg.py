#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers
import random

with atheris.instrument_imports(include=['cairosvg']):
    import cairosvg

from urllib.error import URLError
from xml.etree.ElementTree import ParseError
from gzip import BadGzipFile
from zlib import error
from http.client import InvalidURL
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 2)
    try:
        if choice == 0:
            cairosvg.svg2png(bytestring=fdp.ConsumeRemainingBytes())
        if choice == 1:
            cairosvg.svg2pdf(bytestring=fdp.ConsumeRemainingBytes())
        elif choice == 2:
            cairosvg.svg2ps(bytestring=fdp.ConsumeRemainingBytes())
    except (ParseError, ValueError, EOFError, BadGzipFile, error, URLError, InvalidURL):
        return -1
    except AttributeError:
        if random.random() > .99:
            raise
        return 0


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
