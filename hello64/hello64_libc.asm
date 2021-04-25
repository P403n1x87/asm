; hello64_libc.asm
;
; A simple x86_64 Hello World application that shows how to use the
; Standard C Library
;
; Copyright (C) 2016 Gabriele N. Tornetta <phoenix1987@gmail.com>. All
; rights reserved.
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.
;
default                 rel

global main

extern printf

;
; Initialised data goes here
;
SECTION .data
hello           db  "Hello World!", 10, 0   ; const char *
hello_len       equ $ - hello - 1            ; size_t
;
; Code goes here
;
SECTION .text

; int main (int argc, char ** argv)
main:
    ; return printf(hello) - hello_len;
    lea     rdi, [hello]
    xor     rax, rax
    call    printf WRT ..plt
    sub     rax, hello_len
