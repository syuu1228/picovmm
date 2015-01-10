all:
	make -C kernel
	make -C tests

clean:
	make -C kernel clean
	make -C tests clean
