noexec: examples/noexec.c lib/libreflect.so lib/libreflect.a
	gcc -g -DDEBUG=1 -Iinclude -Llib -Wall -Wextra -pedantic -o noexec examples/noexec.c -lreflect --static-pie

lib/libreflect.so: src/stack_setup.c src/map_elf.c src/jump.c
	mkdir -p lib
	gcc -Iinclude -Isrc -Iarch/linux/x86_64 -Wall -Wextra -pedantic -o lib/libreflect.so src/stack_setup.c src/map_elf.c src/jump.c -fPIC -shared

lib/libreflect.a: src/stack_setup.c src/map_elf.c src/jump.c
	mkdir -p lib
	gcc -Iinclude -Isrc -Iarch/linux/x86_64 -Wall -Wextra -pedantic -o src/stack_setup.o -c src/stack_setup.c -fPIC
	gcc -Iinclude -Isrc -Iarch/linux/x86_64 -Wall -Wextra -pedantic -o src/jump.o -c src/jump.c  -fPIC
	gcc -Iinclude -Isrc -Iarch/linux/x86_64 -Wall -Wextra -pedantic -o src/map_elf.o -c src/map_elf.c -fPIC
	ar rcs lib/libreflect.a src/*.o
