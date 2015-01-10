CFLAGS=-Wall -Werror -std=c11 -I../kernel -I../libpico
all: vmwrite-vmread libpico-vmentry

libpico-vmentry: libpico-vmentry.o
	gcc -o libpico-vmentry libpico-vmentry.o ../libpico/libpico.a
clean:
	rm -rf vmwrite-vmread libpico-vmentry *.o
