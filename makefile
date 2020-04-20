CC=gcc
CFLAGS=-g
FILES=*.c
EXEC=synflood

raycaster: $(FILES)
	$(CC) $(FILES) $(CFLAGS) -o $(EXEC)
