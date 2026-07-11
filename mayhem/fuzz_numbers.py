#!/usr/bin/env python3

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports(include=["numbers_parser"]):
    from numbers_parser import Document

from numbers_parser.exceptions import NumbersError
from zipfile import BadZipFile
from zlib import error

def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeTemporaryFile('.numbers', all_data=True, as_bytes=True) as numbers_path:
            doc = Document(numbers_path)
    except (NumbersError, OSError, BadZipFile, error, NotImplementedError, UnicodeDecodeError):
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
