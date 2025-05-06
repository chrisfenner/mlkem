[//]: # (SPDX-License-Identifier: CC-BY-4.0)

# AArch64 backend (little endian)

This directory contains a native backend for little endian AArch64 systems. It is derived from [^NeonNTT] [^SLOTHY_Paper].

## Variants

This backend comes in two versions: "clean" and optimized. The "clean" backend is handwritten and meant to be easy to read and modify; for example, is heavily leverages register aliases and assembly macros. This directory contains the optimized version, which is automatically generated from the clean one via [SLOTHY](https://github.com/slothy-optimizer/slothy). Currently, the
target architecture is Cortex-A55, but you can easily re-optimize the code for a different microarchitecture supported
by SLOTHY, by adjusting the parameters in the [Makefile](src/Makefile).

<!--- bibliography --->
[^NeonNTT]: Becker, Hwang, Kannwischer, Yang, Yang: Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72 and Apple M1, [https://tches.iacr.org/index.php/TCHES/article/view/9295](https://tches.iacr.org/index.php/TCHES/article/view/9295)
[^SLOTHY_Paper]: Abdulrahman, Becker, Kannwischer, Klein: Fast and Clean: Auditable high-performance assembly via constraint solving, [https://eprint.iacr.org/2022/1303](https://eprint.iacr.org/2022/1303)
