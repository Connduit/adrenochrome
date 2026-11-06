# Adrenochrome

Adrenochrome is an experimental Windows C/C++ project for studying reflective DLL loading, manual PE mapping, and a proposed custom module format called **AXE**. The original design notes reference Athena as an inspiration. The repository contains a command-line builder, loader and installer DLLs, a demonstration engine, and scaffolding for additional modules.

The implementation is a work in progress. Several features described in the archived READMEs are plans or experiments rather than working capabilities.

## Analysis archive workflow

The builder now writes a **non-executing AXE analysis archive**. It preserves the complete input DLL and provides `pack`, `inspect`, and `extract` commands. This is deliberately a separate format from the unfinished runtime AXE structures: **do not pass these archives to the existing loader**. No loader or mapping code was changed.

See [the analysis archive specification and tests](builder/ANALYSIS_ARCHIVE.md).

## What is implemented

| Component | Current role |
| --- | --- |
| `builder/` | Console application for packing, inspecting, and extracting non-executing analysis archives containing the complete DLL. |
| `installer/` | Experimental DLL that attempts to load the loader into another Windows process. It contains developer-specific paths and interactive debug dialogs. |
| `loader/` | Reflective loading code and a disk-loading experiment that passes file contents to the PE manual mapper. The separate AXE mapping experiment is commented out. |
| `common/` | Shared PE structures, AXE structures, manual mapping, and module/export lookup helpers. |
| `engine/` | Demonstration DLL with message-box diagnostics and an exported `AxeEntry` function. |
| `beacon/`, `command/`, `uninstaller/` | Placeholder modules with message-box DLL entry points; networking, command execution, and uninstall logic are not implemented in their corresponding source files. |

The intended architecture separates module preparation, loading, and engine functionality. The analysis archive preserves the original DLL byte for byte inside a versioned container. It does **not** demonstrate header removal, encryption, compression, or conversion to position-independent code. `DllConverter` and `Packer` are scaffolding, and `converter.cpp` contains commented pseudocode.

## Component purposes and behavior

### Builder: prepare files for the loading experiments

`builder/` is the development-time tool, compiled as `builder.exe`. Its intended purpose is to turn a normal Windows DLL into an AXE module and eventually package modules for the runtime components.

The current executable enters through [`builder/src/main.cpp`](builder/src/main.cpp) and delegates to `AxeArchive.cpp`. It validates basic PE DLL structure, preserves the complete file in an analysis container, reports section metadata, and can extract the original bytes. It never loads or executes the contents. The former single-input copy CLI has been replaced by explicit subcommands.

The rest of the directory records the larger design:

- `Builder.cpp` contains a separate, unfinished conversion path for reading a PE image, collecting section and relocation information, and constructing AXE metadata. The CLI does not call that path.
- `AxeBuilderContext.h` groups the proposed header, sections, imports, and relocations while a module is being constructed.
- `AxeConfig.h` lists sections the experimental conversion path intends to retain. It is a source-level configuration structure, not a configuration file accepted by the CLI.
- `DllConverter` declares AXE and PIC (position-independent code) targets, but its conversion cases have no implementation.
- `Packer` is a placeholder for packaging; its source comments propose encryption and compression, but neither is implemented there.

The old `AdrenochromeBuilder` conversion and `basicBuild` code remain in the tree but are not called by the CLI. Analysis archive tests validate storage and extraction, not executable loading or the experimental runtime AXE format.

### Installer: experimental bootstrap DLL

`installer/` builds `installer.dll`. Despite the name, it is not a conventional setup program: the current source does not implement an installation wizard, application registration, or a corresponding uninstall procedure.

Its purpose in the prototype is to initiate loading of another DLL into a Windows process. Its DLL entry point starts a worker thread; that worker selects a process, reads the loader file, and delegates to the shared loading helper. Debug message boxes report progress and some failures.

[`installer/src/Installer.c`](installer/src/Installer.c) contains the implementation and its environment assumptions. File locations and the selected process are fixed in source rather than supplied through a supported runtime configuration interface. The component is an experimental bootstrap, with Windows-specific dependencies and incomplete error handling.

### Loader: runtime loading and engine handoff

`loader/` builds `loader.dll`. Its purpose is to bridge module loading and engine startup. It contains two related entry paths:

- `ReflectiveLoader.c` exposes the reflective entry point and uses the shared PE mapping helpers. The active implementation receives a raw image address through its parameter and checks PE signatures. An alternative image-discovery implementation also exists, but is not the active entry path.
- `LoaderDll.c` contains the regular DLL entry point. On process attachment, it displays a diagnostic and starts a thread that calls `startEngine`.

[`loader/src/Loader.c`](loader/src/Loader.c) implements that engine handoff. `startEngine` calls the disk-loading experiment, which reads a file from a hard-coded path and passes its contents to the shared `ManualMap` function. Although the file and function names refer to AXE, the active mapper consumes a PE image. This previously matched the old `basicBuild` copy behavior. It does not accept the new analysis archive wrapper.

The separate code for interpreting custom AXE headers and sections is commented out. Several other functions, including PIC loading and section-based loading, are empty placeholders. The archived notes' broader module registration and export-forwarding design should not be read as implemented runtime behavior.

### Common: shared binary-format and mapping support

`common/` supplies supporting code and headers; it is not a standalone executable or DLL project. The Makefile links its C objects into the four targets it builds.

Its main responsibilities are:

- `ManualMap.c`: PE image mapping support, including image layout, relocation adjustment, import resolution, and invocation of the mapped image's DLL entry point.
- `LoadLibraryManual.c`: the shared helper used by the bootstrap experiment to initiate reflective loading in another process.
- `GetModuleHandleManual.c` and `GetProcAddressManual.c`: lookup helpers that identify loaded modules and exported functions using hashed names.
- `PEStructs.h`: Windows and PE-related structures, function types, and mapping context definitions.
- `AXEStructs.h`: proposed custom AXE header, section, import, and relocation structures. These definitions describe an experimental format; they do not mean the active CLI serializes that format.
- `Utils.h`, `AdrenochromeHashes.h`, and `StatusCodes.h`: hashing utilities, lookup constants, and status-code definitions used by the loading code.

This is a partial implementation of functionality normally handled by the Windows loader. The top-level `ManualMap` function does not consistently check intermediate results, and there is no automated compatibility suite establishing support for arbitrary DLLs. Comments about the full Windows loading lifecycle should not be treated as proof that every part is handled.

### Engine: demonstration of module entry

`engine/` builds `engine.dll`, the demonstration module the loading experiments are intended to reach. It provides two distinct entry points:

- `EngineDll.c` implements the normal `DllMain`, which shows a message box on process attachment.
- `Engine.c` exports `AxeEntry`, which shows a separate message box when explicitly called.

These diagnostics distinguish ordinary DLL initialization from the proposed custom module entry. The active shared mapper calls the PE DLL entry point; the presence of an `AxeEntry` export does not make it the automatically selected entry point.

The source comments envision an engine that initializes shared functionality for other modules. The present engine does not implement that service layer, a module manager, or a communications loop.

### Beacon: placeholder for a communications module

`beacon/` is a separate DLL project in the Visual Studio solution. Its name suggests the communications role anticipated by the design, but its current implementation is only a DLL skeleton. `Beacon.c` includes its header, and `BeaconDll.c` displays a message box when attached to a process.

There is no implemented endpoint configuration, network transport, periodic callback, or message-processing loop in this component. It is not included in the Linux Makefile's targets.

### Command: placeholder for a command module

`command/` is another Visual Studio DLL project. It reserves a component boundary for command-related functionality, but `Command.c` currently only includes its header and `CommandDll.c` displays an attachment diagnostic.

No command parser, dispatcher, or execution interface is implemented. The directory name does not imply a working remote-command facility. It is not built by the Linux Makefile.

### Uninstaller: placeholder for cleanup functionality

`uninstaller/` is the Visual Studio DLL project reserved for eventual cleanup or removal functionality. Its current source follows the same skeleton as the beacon and command modules: a header include and a DLL entry point that displays a message box.

It does not undo the bootstrap experiment, remove files, restore configuration, or unload other modules. There is no implemented installer/uninstaller lifecycle. It is also absent from the Linux Makefile's targets.

### Build definitions: two development entry points

`adrenochrome.sln` and the component `.vcxproj` files describe the Windows Visual Studio build, including all seven component projects. Each project's source list and settings determine what is compiled; shared files are not a separate solution project.

The root `Makefile` provides a smaller Linux-to-Windows cross-compilation workflow for the builder, installer, loader, and engine. Both workflows produce Windows binaries. Differences in target coverage and compiler settings mean success with one workflow does not establish success with the other.

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

## Run and test the analysis builder

The analysis CLI can be built independently on Linux without Windows headers or the loading components:

```sh
g++ -std=c++17 -Wall -Wextra -Werror -Ibuilder/include \
  builder/src/main.cpp builder/src/AxeArchive.cpp -o /tmp/axe-analysis-builder
/tmp/axe-analysis-builder pack input.dll output.axe
/tmp/axe-analysis-builder inspect output.axe
/tmp/axe-analysis-builder extract output.axe restored.dll
python3 builder/tests/test_archive.py /tmp/axe-analysis-builder
```

On Windows, the equivalent commands use the built `builder.exe`. Output paths must not already exist. The input limit is 256 MiB. Errors return status 1; incorrect command syntax returns status 2. Archives preserve the entire DLL and are for data inspection only. The test fixture contains synthetic PE metadata and data, and is never executed.

## Historical DLL prototype workflow on Windows

**Compatibility:** The following describes the pre-existing runtime experiment, which has not been updated for analysis archives. Archives made by the new `pack` command are incompatible with this workflow.

The current manual workflow uses an external DLL injector. The maintainer uses **Xenos**, with its injection type set to **Native Injection** for the initial `installer.dll` load.

1. Open a process to host `installer.dll`, such as **Notepad** (`notepad.exe`).
2. Open **Microsoft Paint** before loading the installer. The installer currently searches specifically for `mspaint.exe`; this target is hard-coded.
3. In Xenos, select the initial host process (for example, Notepad), choose `installer.dll`, and use **Native Injection**.
4. The installer's worker then attempts to load `loader.dll` into **Paint**, using the project's reflective loading and manual mapping code.
5. Once initialized in Paint, `loader.dll` attempts to read `engine.axe` from disk and load it using the shared manual mapper.

The two DLLs have different roles: `installer.dll` runs in the initial host process and bootstraps the next stage; `loader.dll` is the DLL reflectively loaded and manually mapped into `mspaint.exe`. The injector's **Native Injection** setting applies to the initial installer load. The subsequent reflective load is performed by the project's own code. Use separate processes for these stages.

`engine.axe` is intended to be a custom DLL-derived module that retains the sections and metadata required for loading while removing standard PE identifying information and other unnecessary content. This is the intended AXE design, rather than a guarantee that all identifying information can be removed. The former `basicBuild` path copied the DLL unchanged to `.axe`, and the loader passes those bytes to the PE manual mapper. The new analysis CLI wraps the original file in an archive instead; the runtime loader does not support that wrapper. The custom stripped-format conversion and its corresponding AXE-specific loading path remain unfinished.

The overall sequence is: **external injector → installer in the initial host → loader in Paint → attempt to manually map `engine.axe`**. The engine is the demonstration module reached by that final stage; its current behavior is to display diagnostic message boxes.

Before running, check the paths compiled into `installer/src/Installer.c` and `loader/src/Loader.c`. The installer expects `loader.dll` at a developer-specific Debug or Release location, depending on build definitions. After loading, the loader attempts to read `engine.axe` from another hard-coded path, currently under the original author's `x64/Release` directory. Building the DLLs alone does not configure these locations.

This is a manual prototype workflow reported by the maintainer, not an automated test. It depends on Windows, those file paths, the expected processes, and interactive debug dialogs. The DLL components have no standalone application launcher, and there is no portable, automated end-to-end run command in this checkout. This workflow has not been executed in the Linux cloud environment; the archive tests above do not exercise it.

## Test and validation status

The analysis builder has a Python regression suite covering archive round trips, metadata inspection, invalid inputs, corruption, overwrite protection, and CLI failures. There is no `make test` target or checked-in CI workflow. Runtime loading still has no automated test suite.

To force a fresh Linux build without deleting existing outputs:

```sh
check_dir=$(mktemp -d)
make -j4 OBJ_DIR="$check_dir/obj" BIN_DIR="$check_dir/bin" \
  CC='x86_64-w64-mingw32-gcc -include stdio.h' \
  CXX=x86_64-w64-mingw32-g++
file "$check_dir"/bin/*
```

For the cloud toolchain, use the PATH export and `-posix` compiler names shown above. Expect x86-64 PE32+ files: three DLLs and one executable. Artifact inspection confirms file format, not runtime correctness.

All four Makefile targets were freshly cross-compiled with MinGW GCC 14 during cloud setup. The analysis CLI and its Python regression suite run natively on Linux. Windows execution, native Visual Studio builds, and x86 builds have not been verified in that environment.

Known limitations to account for during development:

- `installer/src/Installer.c` and `loader/src/Loader.c` contain hard-coded Windows paths and runtime assumptions.
- AXE format definitions and conversion code are unfinished; the analysis CLI preserves the complete DLL within its separate archive format.
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
