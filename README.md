# Adrenochrome

Adrenochrome is an experimental Windows C/C++ project for studying reflective DLL loading, manual PE mapping, and a proposed custom module format called **AXE**. The original design notes reference Athena as an inspiration. The repository contains a command-line builder, loader and installer DLLs, a demonstration engine, and scaffolding for additional modules.

The implementation is a work in progress. Several features described in the archived READMEs are plans or experiments rather than working capabilities.

## What is implemented

| Component | Current role |
| --- | --- |
| `builder/` | Console application. Its active `basicBuild` path copies input bytes to a sibling file with an `.axe` extension. |
| `installer/` | Experimental DLL that attempts to load the loader into another Windows process. It contains developer-specific paths and interactive debug dialogs. |
| `loader/` | Reflective loading code and a disk-loading experiment that passes file contents to the PE manual mapper. The separate AXE mapping experiment is commented out. |
| `common/` | Shared PE structures, AXE structures, manual mapping, and module/export lookup helpers. |
| `engine/` | Demonstration DLL with message-box diagnostics and an exported `AxeEntry` function. |
| `beacon/`, `command/`, `uninstaller/` | Placeholder modules with message-box DLL entry points; networking, command execution, and uninstall logic are not implemented in their corresponding source files. |

The intended architecture separates module preparation, loading, and engine functionality. Today, an `.axe` file produced by the CLI is still the original input file byte for byte. It does **not** demonstrate header removal, encryption, compression, or conversion to position-independent code. `DllConverter` and `Packer` are scaffolding, and `converter.cpp` contains commented pseudocode.

## Requirements

- Windows development: Visual Studio 2022 with **Desktop development with C++**, the MSVC v143 toolset, and a Windows SDK compatible with the projects' `10.0` SDK setting.
- Linux cross-compilation: GNU Make and the MinGW-w64 x86-64 C and C++ compilers. The builder uses C++17.
- Runtime: Windows for the generated executables and DLLs. Linux compilation alone does not validate loading behavior.

The solution declares Debug/Release and x64/x86 configurations. Use x64 as the initial development target; x86 runtime compatibility has not been established. No package-manager dependencies or server services are declared for this build.

## Build on Windows

Open `adrenochrome.sln` in Visual Studio and select **Debug / x64**.

The project files currently contain absolute include paths under the original author's checkout. Before building on another machine, use a local property sheet or update your local project settings so **C/C++ → General → Additional Include Directories** includes:

- `common/include` for projects that use the shared headers.
- The relevant component's `include` directory.

Use absolute paths to your own checkout or project-relative paths such as `$(ProjectDir)include` and `$(ProjectDir)..\common\include`. Apply the settings to the configurations you intend to build. This path adjustment is a prerequisite; an untouched solution is not portable as checked in.

Build the solution in the IDE, or run this from a Visual Studio Developer Command Prompt at the repository root after configuring the include paths:

```bat
msbuild adrenochrome.sln /m /p:Configuration=Debug /p:Platform=x64
```

The solution includes all seven component projects. Check the build output for the actual artifact paths; the runtime source also contains absolute paths that are independent of the build output directory. Native MSVC builds have not been verified in the Linux cloud environment.

## Cross-compile on Linux

On Debian/Ubuntu machines with package-install privileges:

```sh
sudo apt-get update
sudo apt-get install make gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64
```

From the repository root:

```sh
make -j4 CC='x86_64-w64-mingw32-gcc -include stdio.h' \
  CXX=x86_64-w64-mingw32-g++
```

The forced include supplies the declaration of `sprintf_s` missing from one C translation unit; GCC 14 otherwise rejects it. It preserves the checked-in source and normal compiler diagnostics.

The Makefile produces:

```text
bin/installer.dll
bin/loader.dll
bin/builder.exe
bin/engine.dll
```

It does not build the beacon, command, or uninstaller projects. Objects go into `obj/`. The Makefile does not generate header dependencies, so use fresh object directories after header or compiler-option changes.

In the prepared cloud environment, the locally extracted MinGW toolchain uses explicit POSIX compiler names:

```sh
export PATH=/workspace/toolchains/mingw/usr/bin:$PATH
make -j4 CC='x86_64-w64-mingw32-gcc-posix -include stdio.h' \
  CXX=x86_64-w64-mingw32-g++-posix
```

## Run and smoke-test the builder

The executable accepts one input-file path. It writes a sibling file with the extension replaced by `.axe`, overwriting that output if it exists. The current implementation does not validate that the input is a DLL.

The following PowerShell smoke test uses a temporary text fixture to verify the actual CLI behavior without loading code. Set `$builder` to the absolute path of your Windows-built `builder.exe` (or a cross-built executable with its required MinGW runtime DLLs available):

```powershell
$builder = (Resolve-Path '.\x64\Debug\builder.exe').Path
$scratch = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    $inputFile = Join-Path $scratch 'fixture.txt'
    $outputFile = Join-Path $scratch 'fixture.axe'
    [IO.File]::WriteAllText($inputFile, 'adrenochrome copy smoke test')
    & $builder $inputFile
    if (!(Test-Path $outputFile)) { throw 'Builder did not create the output' }
    if ((Get-FileHash $inputFile).Hash -ne (Get-FileHash $outputFile).Hash) {
        throw 'Output differs from input'
    }
    'PASS: builder created an identical .axe copy'
} finally {
    Remove-Item -Recurse -Force $scratch
}
```

Check output existence and contents explicitly: `main` ignores the boolean returned by `basicBuild`, so its exit status does not reliably report copy failures. With no arguments it prints `Not enough arguements`; more than one input argument is silently ignored.

The DLL components have no standalone application launcher. Their current runtime experiments depend on Windows, developer-specific paths, and interactive dialogs. There is no portable, automated end-to-end run command in this checkout. The builder smoke test above does not exercise reflective loading or manual mapping.

## Test and validation status

There is no automated test suite, `make test` target, or checked-in CI workflow. The available validation consists of compilation, artifact inspection, and manual Windows checks.

To force a fresh Linux build without deleting existing outputs:

```sh
check_dir=$(mktemp -d)
make -j4 OBJ_DIR="$check_dir/obj" BIN_DIR="$check_dir/bin" \
  CC='x86_64-w64-mingw32-gcc -include stdio.h' \
  CXX=x86_64-w64-mingw32-g++
file "$check_dir"/bin/*
```

For the cloud toolchain, use the PATH export and `-posix` compiler names shown above. Expect x86-64 PE32+ files: three DLLs and one executable. Artifact inspection confirms file format, not runtime correctness.

All four Makefile targets were freshly cross-compiled with MinGW GCC 14 during cloud setup. Windows execution, the PowerShell smoke test, native Visual Studio builds, and x86 builds have not been verified in that environment.

Known limitations to account for during development:

- `installer/src/Installer.c` and `loader/src/Loader.c` contain hard-coded Windows paths and runtime assumptions.
- AXE format definitions and conversion code are unfinished; the active CLI preserves PE headers by copying the entire file.
- Compiler warnings remain, including a returned pointer to a local variable in `AdrenochromeBuilder::getAXESection`. Successful compilation does not establish that those experimental paths are correct.
- The Windows projects and Linux Makefile cover different sets of components.

## Archived design notes

The original documentation is preserved unchanged:

- [Original root README](README_old.md)
- [Original builder notes](builder/README_old.md)
- [Original loader notes](loader/README_old.md)

These files include proposed features and historical experiments. Use the current source and the implementation status above to determine what is available.

## License

See [LICENSE](LICENSE) for the included GNU GPL v3 license text.
