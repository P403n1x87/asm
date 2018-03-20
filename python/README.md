# Sample Assembly extension for Python

This is a sample assembly extension for Python written in x86-64 assembly
for the Netwide Assembler (NASM) and Linux platforms.

## Installation

To assemble the code use

```bash
make
```

To install the library use
```bash
make install
```
This might require superuser permissions to work.

To uninstall the library use
```bash
make uninstall
```

## Testing with Docker

The project include a `Dockerfile` to test the library with Docker.
Make sure that the `PYTHON_TARGET` variable defined in it specifies
the version of Python that is going to be installed with the latest
image from Ubuntu (e.g. `ENV PYTHON_TARGET=3.5` if the version of
Python that gets installed is 3.5).
