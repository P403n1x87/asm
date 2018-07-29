; minichroot.asm - Copyright (C) 2018 Gabriele Tornetta. All rights reserved.
;
; Minimal version of the UNIX chroot(2) utility.
;
; This application changes the root to the path specified at the command line
; and starts /bin/bash from within the new root file system.
;

global _start

;
; CONSTANTS
;
SYS_WRITE   equ   1
SYS_EXECVE  equ  59
SYS_EXIT    equ  60
SYS_CHDIR   equ  80
SYS_CHROOT  equ 161

STDOUT      equ   1


;; Initialised data
SECTION .data
str_no_path db "Wrong number of arguments. Use as: minichroot /new/root/path", 0
str_no_ent  db "No such file or directory.", 0
str_perm    db "Operation not permitted.", 0

lf          db 10     ; const char *

bash        db "/bin/bash", 0
bash_arg    db "-i", 0
bash_argv   dq bash, bash_arg, 0

;; Uninitialised data
SECTION .bss
retval resb 8

;; Code
SECTION .text

_start:
  mov     rcx, [rsp]
  cmp     rcx, 2
  jne      _no_path

  push    rcx

  mov     rdi, [rsp + 8 * 3]
  mov     rax, SYS_CHDIR
  syscall

  ; mov     rdi, [rsp + 8 * 3]
  mov     rax, SYS_CHROOT
  syscall
  cmp     rax, -2
  je      _no_ent
  cmp     rax, -1
  je      _perm

  pop     rcx

  lea     rdx, [rsp + 8 * rcx + 16]
  mov     rsi, bash_argv
  mov     rdi, bash
  mov     rax, SYS_EXECVE
  syscall

  cmp     rax, -2
  je      _no_ent
  cmp     rax, -1
  je      _perm

  jmp     _exit

  _no_path:
  mov     edi, str_no_path
  jmp     _error
  _no_ent:
  mov     edi, str_no_ent
  jmp     _error
  _perm:
  mov     edi, str_perm
  _error:
  call    print

  _exit:
  mov     rax, SYS_EXIT
  xor     rdi, rdi
  syscall

  _no_exit:
  nop
;;;;;; end _start


;;
;; void print(char *)
;;
print:
  mov     rsi, rdi
  mov     rdi, STDOUT
  mov     rdx, 1

  print_repeat:
  xor     rax, rax
  mov     al, [rsi]
  test    rax, rax
  jz      print_return

  mov     rax, SYS_WRITE
  syscall

  inc     rsi
  jmp     print_repeat

  print_return:
  mov     rsi, lf
  mov     rax, SYS_WRITE
  syscall

  ret
;;;;;; end print
