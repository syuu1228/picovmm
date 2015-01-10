all:
	make -C kernel
	make -C libpico
	make -C tests

clean:
	make -C kernel clean
	make -C libpico clean
	make -C tests clean
