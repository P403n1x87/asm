# Copyright (C) 2016 Gabriele N. Tornetta <phoenix1987@gmail.com>. All
# rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY# without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

SHELL:=/bin/bash
APP=hello64

.PHONY: all inc libc libc2 clean

default:
	nasm -f elf64 ${APP}.asm
	ld -s -o ${APP} ${APP}.o -I/lib64/ld-linux-x86-64.so.2
	rm ${APP}.o

inc:
	nasm -f elf64 ${APP}_inc.asm
	ld -o ${APP}_inc ${APP}_inc.o -I/lib64/ld-linux-x86-64.so.2
	strip `while IFS='' read -r line || [[ -n "$$line" ]]; do read s _ <<< $$line; echo -n "-N $$s "; done < <(tail -n +26 ../syscalls.inc)` ${APP}_inc
	rm ${APP}_inc.o

libc:
	nasm -f elf64 ${APP}_libc.asm
	gcc -s -o ${APP}_libc ${APP}_libc.o
	rm ${APP}_libc.o

libc2:
	nasm -f elf64 ${APP}_libc2.asm
	ld -s -o ${APP}_libc2 ${APP}_libc2.o -I/lib64/ld-linux-x86-64.so.2 -lc
	strip -R .hash -R .gnu.version -R .eh_frame hello64_libc2
	rm ${APP}_libc2.o

clean:
	rm hello64 hello64_inc hello64_libc hello64_libc2

all: default inc libc libc2
