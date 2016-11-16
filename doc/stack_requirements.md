Stack Requirements for a Process Image
======================================

The SysV ABI dictates how the stack for each process must be set up.
Additionally, each operating system and libc adds some extra sauce that can
complicate things. Below is the template stack required by `mettle.bin` process
image. Note that the *top* (lowest address value) of the stack must be aligned.
Also note that we do not obey the SysV ABI since we have a file descriptor as
ARGV[1] instead of a `char *`.

```
low                    (each cell is sizeof(void *))
sp % 16 == 0     +---------------------------------------+
                 |              ARGC = X                 |
                 |---------------------------------------|
                 |         ARGV[0] = char * ["m"]        |
                 |---------------------------------------|
                 |         ARGV[1] = sock_fd             |
                 |---------------------------------------|
                 |     [ ... not used by mettle ...]     |
                 |---------------------------------------|
                 |            NULL (Ends ARGV)           |
                 |---------------------------------------|
                 |  0 or more char * to ENV strings of   |
                 |   form VAR=value none are used by     |
                 |                mettle                 |
                 |---------------------------------------|
                 |            NULL (Ends ENV)            |
                 |---------------------------------------|
                 |             AT_BASE (7)               |
                 |---------------------------------------|
                 |   [ address of mmap'd mettle.bin ]    |
                 |---------------------------------------|
                 |             AT_NULL (0)               |
                 |---------------------------------------|
                 |            NULL (Ends AUXV)           |
high             +---------------------------------------+
```
