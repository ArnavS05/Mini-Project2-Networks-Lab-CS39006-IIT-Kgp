CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11

all: smserver smclient

smserver: smserver.c
	$(CC) $(CFLAGS) smserver.c -o smserver

smclient: smclient.c
	$(CC) $(CFLAGS) smclient.c -o smclient

clean:
	rm -f smserver smclient
