# AiDA

> **THIS REPOSITORY IS ACTIVELY MAINTAINED.** Development is live, commits land frequently, and the project is under very active construction. **Contributors are welcome** — feel free to open issues, start discussions, and submit pull requests. If you want to help, jump in: bug reports, feature ideas, documentation, tests, and code are all appreciated. If you plan a large change, open an issue first so we can coordinate, because big refactors land often and we don't want you rebasing onto a moving floor.

![Maintenance](https://img.shields.io/badge/maintenance-active-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-blue)
![Qt](https://img.shields.io/badge/Qt-6.8.3%20msvc2022__64-41CD52)
![C++](https://img.shields.io/badge/C%2B%2B-17%20%2F%2020-00599C)
![Build](https://img.shields.io/badge/build-CMake%203.25%2B%20%2B%20Ninja%20%2B%20MSVC%202022-critical)

---

## Table of Contents

- [What is AiDA?](#what-is-aida)
- [Feature Overview](#feature-overview)
- [Repository Layout](#repository-layout)
- [Building From Source](#building-from-source)
  - [Prerequisites](#prerequisites)
  - [Qt 6.8.3 — Exact Version and Setup](#qt-683--exact-version-and-setup)
  - [Vendored Dependencies (In This Repo)](#vendored-dependencies-in-this-repo)
  - [Provisioned Dependencies (.deps)](#provisioned-dependencies-deps)
  - [Build Commands](#build-commands)
  - [Kernel Driver (WhosWho + WindMapper)](#kernel-driver-whoswho--windmapper)
  - [IDA Pro Plugin](#ida-pro-plugin)
- [Running AiDA](#running-aida)
- [MCP Servers and Tooling](#mcp-servers-and-tooling)
- [Testing](#testing)
- [Privacy and Security Model](#privacy-and-security-model)
- [Contributing](#contributing)
- [Responsible Use](#responsible-use)
- [Third-Party Notices and Acknowledgements](#third-party-notices-and-acknowledgements)

---

## What is AiDA?

AiDA is a Windows reverse-engineering toolkit that ships in three cooperating forms:

1. **AiDA Standalone** (`AiDAStandalone.exe`) — a full desktop IDE for reverse engineering: disassembly, decompilation, debugging, memory scanning, network analysis, AI-assisted chat, and an in-app Test Lab. It boots straight into the IDE — no license screen, no activation, no network requirement.
2. **AiDA IDA Pro plugin** — embeds AiDA's analysis surface inside IDA Pro and exposes it over a localhost MCP server, so AI agents and external tools can drive IDA analysis, decompilation, renaming, patching, typing, commenting, and more.
3. 
## Repository Layout

| Path | Contents |
|---|---|
| `src/` | Windows C++ implementation: IDA plugin + shared code + the standalone IDE (`src/standalone/`) |
| `src/standalone/src/qt/` | The Qt 6.8.3 UI (active port; the legacy ImGui/DX11 UI is being retired) |
| `src/standalone/src/core/` | Standalone core: AI/providers, MCP server/tools, RE/disasm/debugger/scanner, network/Burp tooling, sessions, Test Lab |
| `driver/` | WhosWho KMDF driver + user-mode `voyager::device_t` communication API (`driver/comm.h/.cpp`) |
| `mapper/` | WindMapper manual-map loader for WhosWho.sys |
| `sources/ghidra/` | Vendored, modified sparse tree of NSA Ghidra **12.1.2** (`Ghidra_12.1.2_build`) — decompiler sources + SLEIGH processor specs used directly by the build |
| `sources/Triton/` | Vendored Triton source (symbolic execution), consumed by CMake at this exact path |
| `libdecomp/` | Vendored [libdecomp](https://github.com/dmaivel/libdecomp) source (decompiler framework) |
| `.deps/MemPDB/` | Vendored [MemPDB](https://github.com/nikgeneburn/MemPDB) fork with local changes — in-memory kernel PDB symbol engine |
| `cmake/` | CMake modules, including the Qt 6.8.3 dependency gate |
| `tools/` | Build/development utilities |
| `docs/` | Documentation |
| `build-host.cmd` | The supported build wrapper (see below) |

## Building From Source

### Prerequisites

| Requirement | Exact version / notes |
|---|---|
| OS | Windows 10/11 x64 |
| Compiler | MSVC 2022 (v143 toolset), C++17 — one TU (`kernel_symbols.cpp`) compiles as C++20 |
| Build system | **CMake 3.25+** with the **Ninja** generator |
| Qt | **Qt 6.8.3, `msvc2022_64` build — this exact version** (details below) |
| Python | Python 3.12 on PATH (runs `src/encrypt_whoswho.py` for the driver embed step) |
| Assembler | MASM (`ASM_MASM`, ships with MSVC) |
| IDA SDK | Only for the IDA plugin target; not required for the standalone IDE |

## Contributing

You are welcome here. Some ground rules so contributions land smoothly:

1. **Open an issue before large changes.** The codebase moves fast (the Qt port touches hundreds of files); coordination avoids painful rebases.
2. **Read `AGENTS.md` first.** It documents the build system, the driver rebuild pipeline, directory guide, conventions, and the diagnostics lessons we already learned the hard way.
3. **Conventions that matter:**
   - Windows-first C++ (C++17; `kernel_symbols.cpp` is C++20), CMake 3.25+ / Ninja / MSVC.
   - No code comments/docstrings/TODOs in source — code must be self-explanatory (CMake `COMMENT` strings are fine).
   - No stubs, placeholders, or dead code — implementations must be complete and production-grade.
   - Kernel code: `ExAllocatePool2`, pool tags, `RtlSecureZeroMemory`, SEH, explicit IRQL checks; never touch paged pool under a spin lock.
   - Long-running work goes on the existing `work_queue`; initialize/shutdown pairs stay balanced; preserve cancellation tokens.
   - Do not break the driver bridge, the debugger, or the Win32 message pump. The message-pump invariants in `src/standalone/src/main.cpp` are documented in `AGENTS.md` — honor them.
   - No protection/obfuscation/anti-tamper mechanisms. They were deliberately removed; do not reintroduce them.
   - Never commit secrets, API keys, or user-private material.
4. **Driver changes** follow the driver rebuild pipeline above and always come with a "reboot required" note.
5. **Evidence over speculation** for bug reports: include `aida_debug.log` excerpts, repro steps, and environment details.

## Responsible Use

AiDA is a reverse-engineering toolkit with a kernel driver. Use it only on systems, binaries, and data you are authorized to analyze. Loading kernel drivers and intercepting network traffic carry real risk to the host machine — you are responsible for your own analysis environment. This project is provided as-is, without warranty of any kind.

## Third-Party Notices and Acknowledgements

AiDA builds on the work of others — thank you:

- **Ghidra 12.1.2** (National Security Agency, Apache-2.0) — embedded decompiler + SLEIGH specs; notices in `src/standalone/third_party_notices/Ghidra-LICENSE.txt` and `Ghidra-NOTICE.txt`
- **Qt 6.8.3** (The Qt Company, LGPL-3.0/commercial) — dynamically linked, runtime staged via `windeployqt`
- **Qt Advanced Docking System 4.4.1** (LGPL-2.1)
- **Triton** (Apache-2.0), **libdecomp**, **MemPDB**, **Z3** (MIT), **Capstone**, **Zydis**, **Unicorn**, **LIEF**, **LLVM**, **Taskflow**, **mimalloc**, **PCRE2**, **zstd**, **liblzma**, **nghttp2**, **llhttp**, **brotli**, **SQLite**, **Lua**, **sol2**, **parallel-hashmap**, **concurrentqueue**, **nlohmann json-schema-validator**, **AngelScript**, **Bitwuzla**, **Camoufox**
- Fonts: **Inter** and **JetBrains Mono** (SIL OFL — notices in `src/standalone/third_party_notices/`)
- Dear ImGui (legacy UI, being retired by the Qt port)

Each vendored dependency retains its own LICENSE file in its directory; additional notices live in `src/standalone/third_party_notices/`.

---

*If you find AiDA useful, star the repo, file issues when things break, and send PRs when you fix them. Happy reversing.*
