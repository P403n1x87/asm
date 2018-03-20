default: build

build:
	nasm -f elf64 -g asm/asm.asm -o asm/asm.o
	ld -shared -o asm/asm.so asm/asm.o -I/lib64/ld-linux-x86-64.so.2

clean:
	rm asm/asm.so asm/asm.o

install: default
	cp asm/asm.so /usr/lib/python${PYTHON_TARGET}/asm.so

uninstall:
	rm /usr/lib/python${PYTHON_TARGET}/asm.so
