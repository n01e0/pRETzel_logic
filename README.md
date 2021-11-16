# pRETzel logic

pRETzel logic is a ROP-based obfuscating compiler implemented on LLVM

## Usage

The -mrop-obfuscate flag can be used to ROP-obfuscate all functions.
It also supports per-function obfuscation by adding the rop_obfuscate attribute to LLVM-IR.

```sh
$ clang -mrop-obfuscate src.c
```
