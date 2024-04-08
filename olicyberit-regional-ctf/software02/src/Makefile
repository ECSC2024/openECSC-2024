
CFLAGS = -Wall -Wextra -pedantic -no-pie


ghost: ghost.c ghost.S
	gcc -DFLAG=$(FLAG) $(CFLAGS) -o $@ $^
	strip $@
