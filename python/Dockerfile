FROM  ubuntu:latest
USER  root
ADD   . asm
RUN   apt-get update              &&\
      apt-get install -y            \
        nasm                        \
        python3-pytest              \
        build-essential
ENV   PYTHON_TARGET=3.5
RUN   cd asm                      &&\
      make                        &&\
      make install                &&\
      python3 -m pytest -s
