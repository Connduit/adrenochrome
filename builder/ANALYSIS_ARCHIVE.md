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

## Standalone utility and library

The standalone analysis build produces three artifacts:

- `builder/build/builder`: packs, inspects, and extracts analysis archives.
- `builder/build/axe_extract`: validates an archive and extracts the original DLL to a new file.
- `builder/build/libaxe_archive.a`: reusable C++17 analysis archive library.

From the repository root:

```sh
make -C builder -j4
builder/build/axe_extract -h
builder/build/axe_extract input.axe restored.dll
make -C builder test
```

The utility only writes bytes to disk. It never invokes the runtime loader or
executes the extracted file. The build links only the analysis archive source;
it does not link the legacy conversion code, manual mapper, or injection helpers.

To use the library from another analysis tool, include `AxeArchive.h` and link
`libaxe_archive.a` with a compatible C++17 compiler. Its file-based API is:

```cpp
axe_archive::write(inputPath, archivePath);
axe_archive::inspect(archivePath, reportStream);
axe_archive::extract(archivePath, outputPath);
```

All paths are `std::filesystem::path`; the report destination is `std::ostream&`.
Functions throw standard exceptions on file or validation errors. Extraction
validates the archive before creating its output, and refuses existing output
paths. No runtime loading API is exposed.

For Windows cross-compilation with MinGW, use a separate output directory:

```sh
make -C builder -j4 BUILD_DIR=build/windows EXEEXT=.exe \
  CXX=x86_64-w64-mingw32-g++ AR=x86_64-w64-mingw32-ar
```

The prepared cloud toolchain uses `x86_64-w64-mingw32-g++-posix` after adding its
`usr/bin` directory to PATH. Run native tests on the host build; cross-compiled
Windows executables require Windows and the appropriate MinGW runtime DLLs.
The existing Visual Studio project builds the builder CLI; the new standalone
extractor is built through `builder/Makefile`.

## Build and test on Linux

The standalone build above requires GNU Make, a C++17 compiler, `ar`, and Python 3
for tests. Alternatively, compile the builder directly:

```sh
g++ -std=c++17 -Wall -Wextra -Werror -Ibuilder/include \
  builder/src/main.cpp builder/src/AxeArchive.cpp -o /tmp/axe-analysis-builder
python3 builder/tests/test_archive.py /tmp/axe-analysis-builder
```

The direct test command skips the standalone utility test unless `AXE_EXTRACTOR`
points to a built extractor. `make -C builder test` supplies that path and runs
all tests.

Tests use synthetic PE fixtures containing data only. They exercise archive
encoding, byte-for-byte extraction, section inspection, malformed input, checksum
and header rejection, output preservation, nonzero failure statuses, and the
standalone extraction utility. They do not execute DLLs.

## Formatting

`builder/.clang-format` defines four-space indentation, Allman braces, and a
100-column line limit. To apply it with clang-format 21:

```sh
clang-format -i builder/src/*.cpp builder/include/*.h builder/tools/*.cpp
```

Legacy conversion files are formatted for readability only; their behavior and
unfinished implementation are unchanged.
