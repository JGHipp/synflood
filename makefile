CC=gcc
CFLAGS=-g
FILES=*.c
EXEC=synflood

synflood: $(FILES)
	$(CC) $(FILES) $(CFLAGS) -o $(EXEC)
