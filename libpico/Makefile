CFLAGS=-Wall -Werror -std=c11 -I../kernel

all: libpico
libpico: libpico.o
	ar r libpico.a libpico.o
clean:
	rm -rf *.a *.o
