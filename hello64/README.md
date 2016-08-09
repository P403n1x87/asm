# Hello64

This folder contains four Assembly code example that show how to write NASM code to produce x86_64 application for the Linux OS.

Copyright © 2016 Gabriele N. Tornetta. All rights reserved.

Licence: GPLv3.

## Contents

The files are organised as follows.

### hello64.asm

A pure x86_64 assembly code program that prints `Hello World!` to screen. It shows how to make system calls using the new `syscall` opcode introduced in the x86_64 architectures.

### hello64_inc.asm

Same as `hello64.asm`, but using the `syscalls.inc` file from the parent folder to define the constants associated to the system calls. The `Makefile` contains a command that allows reducing the executable file by removing the symbols introduced by `syscalls.inc`

### hello64_libc.asm

Demonstrates how to use the Standard C Library with NASM code. The source code in this case is structured like a C code, i.e. with the assembly analogue of the `main` function.

### hello64_libc2.asm

This is a hybrid example, where the Standard C Library is only used to provide for standard functions, like `printf`. No analogue of the C's `main` function is implemented and the coder is expected to terminate the application execution herself/himself.
