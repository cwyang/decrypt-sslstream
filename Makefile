CC=gcc
CFLAGS=-I. -g
DEPS=

all: decrypt

demo: decrypt
	./decrypt samples/rsasnakeoil2.key samples/rsasnakeoil2-client samples/rsasnakeoil2-server

%.o: %c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

decrypt: main.o memory.o
	$(CC) -o $@ $^ $(CFLAGS) -lssl -lcrypto
clean:
	rm -f *.o decrypt
