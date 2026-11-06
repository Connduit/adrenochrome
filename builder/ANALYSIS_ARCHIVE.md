# AXE analysis archive, version 1

This format stores a complete DLL for non-executing inspection and extraction.
It is separate from `common/include/AXEStructs.h` and is **not compatible with the
existing runtime loader**. The CLI never allocates executable memory, resolves
runtime imports, applies relocations, or calls code from an input file.

## Commands

```text
builder pack input.dll output.axe
builder inspect input.axe
builder extract input.axe output.dll
builder -h
```

Use `-h` or `--help` for command descriptions, examples, limits, and exit codes.

All output paths must be new. The input and output paths are explicit; no suffix
replacement or implicit overwrite occurs. Return codes: 0 for success, 1 for
file/format errors, 2 for invalid command syntax. Inputs are limited to 256 MiB
and read into memory. Packing temporarily holds both input and archive bytes.

## Storage layout

Integers use unsigned little-endian encoding, written field by field rather than
by serializing C++ structs. There are no pointers, native-sized fields, filenames,
or executable loading instructions in the archive header.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | Magic bytes `AXEARCH` followed by a zero byte |
| 8 | 4 | Version, currently 1 |
| 12 | 4 | Header size, currently 32 |
| 16 | 8 | Original DLL length in bytes |
| 24 | 4 | FNV-1a 32-bit checksum of the original DLL bytes |
| 28 | 4 | Reserved flags, must be zero |
| 32 | Original length | Complete, unchanged DLL bytes |

FNV-1a uses initial value 2166136261 and multiplier 16777619, with unsigned
32-bit arithmetic. It detects accidental corruption; it is not authentication
or protection against intentional modification.

The original PE section table and all other original metadata remain inside the
payload. The reader derives its section report from that table rather than
storing a second potentially inconsistent copy. It reports the PE machine code,
section count, section names, raw offsets, and raw lengths. Non-printable section
name bytes are displayed as `?`.

The reader rejects unsupported versions, flags and header sizes, mismatched
lengths, checksum failures, invalid PE signatures, files without the DLL flag,
invalid optional headers, section counts outside 1–96, truncated section tables,
and section data ranges outside the input. These are structural checks, not a
complete PE conformance check or a guarantee that Windows can load the DLL.

No extraction occurs until the archive and its payload pass validation. Partial
output files are removed after detected write failures. Output directories must
not be concurrently modified: the portable existence check and output creation
are separate operations and do not provide an atomic no-clobber guarantee.

## Build and test on Linux

Run from the repository root:

```sh
g++ -std=c++17 -Wall -Wextra -Werror -Ibuilder/include \
  builder/src/main.cpp builder/src/AxeArchive.cpp -o /tmp/axe-analysis-builder
python3 builder/tests/test_archive.py /tmp/axe-analysis-builder
```

Tests use a synthetic PE fixture containing data only. They exercise archive
encoding, byte-for-byte extraction, section inspection, malformed input, checksum
and header rejection, output preservation, and nonzero failure statuses. They do
not execute DLLs. The Visual Studio builder project and root Makefile also include
the new CLI implementation; old conversion sources remain unused by this CLI.
