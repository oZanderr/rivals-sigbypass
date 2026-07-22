# RivalsSigBypass

An Unreal Engine signature-check bypass for Marvel Rivals that lets unsigned
`.pak`/`.utoc` content mods load. Ships as an `.asi` plugin.

## How it works

The engine verifies content containers against a signing key before mounting them.
This locates the engine's signing-keys getter by pattern scan and replaces it so it
reports no keys, after which unsigned content is accepted.

It is a single prologue patch with no hooking library, `#![no_std]`, x64 only, about
9 KB, and depends only on `windows-sys`.

## Install

1. Install an ASI loader for the game, for example
   [oxiloader](https://github.com/oZanderr/oxiloader) or Ultimate ASI Loader.
2. Drop `RivalsSigBypass.asi` into the loader's plugins folder.
3. Place your content mods where the game reads them.

A prebuilt `RivalsSigBypass.asi` is on the
[Releases](https://github.com/oZanderr/rivals-sigbypass/releases) page.

## Build

Requires the stable `x86_64-pc-windows-msvc` toolchain.

```
cargo build --release
```

The output is `target/release/RivalsSigBypass.dll`; rename it to `RivalsSigBypass.asi`.

## Disclaimer

Modifying a competitive online game client can violate its terms of service and
result in a ban. Use at your own risk.
