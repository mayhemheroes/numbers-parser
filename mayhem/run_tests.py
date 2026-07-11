#!/usr/bin/python3
"""run_tests.py — RUN numbers-parser known-answer assertions and print a parseable summary.

Invoked via the `/mayhem/numbers-tests` ELF launcher (NOT directly), so the verify-repo
sabotage oracle can neuter the launcher and prove the test oracle is behavioral.

This is a self-contained behavioral oracle (no pytest / dev-deps needed): it opens the
bundled known-answer Apple Numbers documents under /mayhem/tests/data and asserts the
parsed cell values / sheet names / exception behavior EXACTLY against the values upstream's
own test suite asserts (tests/test_tables.py). A no-op / exit(0) / behavior-altering patch
to numbers_parser cannot pass it.

It prints one line:

    RUNTESTS tests=<n> passed=<p> failed=<f> skipped=<s>

Exit 0 iff failed == 0. mayhem/test.sh parses that line into a CTRF report.
"""
from __future__ import annotations

import sys

DATA = "/mayhem/tests/data"

# Known-answer references copied verbatim from upstream tests/test_tables.py.
ZZZ_TABLE_1_REF = [
    [None, "YYY_COL_1", "YYY_COL_2"],
    ["YYY_ROW_1", "YYY_1_1", "YYY_1_2"],
    ["YYY_ROW_2", "YYY_2_1", "YYY_2_2"],
    ["YYY_ROW_3", "YYY_3_1", "YYY_3_2"],
    ["YYY_ROW_4", "YYY_4_1", "YYY_4_2"],
]
XXX_TABLE_1_REF = [
    [None, "XXX_COL_1", "XXX_COL_2", "XXX_COL_3", "XXX_COL_4", "XXX_COL_5"],
    ["XXX_ROW_1", "XXX_1_1", "XXX_1_2", "XXX_1_3", "XXX_1_4", "XXX_1_5"],
    ["XXX_ROW_2", "XXX_2_1", "XXX_2_2", None, "XXX_2_4", "XXX_2_5"],
    ["XXX_ROW_3", "XXX_3_1", None, "XXX_3_3", "XXX_3_4", "XXX_3_5"],
]

passed = 0
failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"PASS {name}")
    else:
        failed += 1
        print(f"FAIL {name}")


def main() -> int:
    from numbers_parser import Document
    from numbers_parser.exceptions import FileFormatError

    # --- read a known document and assert exact parsed values ---
    doc = Document(f"{DATA}/test-1.numbers")
    sheets = doc.sheets

    check("sheet count >= 2", len(sheets) >= 2)
    check("sheet[0] name ZZZ_Sheet_1", sheets[0].name == "ZZZ_Sheet_1")

    tables = sheets[0].tables
    data0 = tables[0].rows(values_only=True)
    check("ZZZ_Sheet_1.tables[0] values match", data0 == ZZZ_TABLE_1_REF)

    # XXX table lives in the second sheet (ZZZ_Sheet_2) per upstream tests.
    xxx_tables = sheets["ZZZ_Sheet_2"].tables
    xxx = xxx_tables["XXX_Table_1"].rows(values_only=True)
    check("ZZZ_Sheet_2.XXX_Table_1 values match", xxx == XXX_TABLE_1_REF)

    # Cell-level read parity.
    cell = tables[0].cell("B2")
    check("cell B2 value == YYY_1_1", cell.value == "YYY_1_1")

    # --- assert exception behavior on a non-Numbers input ---
    try:
        Document(f"{DATA}/../conftest.py")
        check("non-numbers raises FileFormatError", False)
    except FileFormatError:
        check("non-numbers raises FileFormatError", True)
    except Exception:
        check("non-numbers raises FileFormatError", False)

    tests = passed + failed
    print(f"RUNTESTS tests={tests} passed={passed} failed={failed} skipped=0")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # import/setup failure is a hard failure, not a vacuous pass
        import traceback

        traceback.print_exc()
        print(f"RUNTESTS tests=1 passed=0 failed=1 skipped=0 (harness error: {exc})")
        sys.exit(1)
