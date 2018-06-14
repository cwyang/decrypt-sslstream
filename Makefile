CC=gcc
CFLAGS=-I. -g
DEPS=

all: decrypt

demo: decrypt
#	./decrypt samples/rsasnakeoil2.key samples/rsasnakeoil2-client samples/rsasnakeoil2-server
	./decrypt samples/somin_tmp2k.pem samples/somin180614-client samples/somin180614-server

%.o: %c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

decrypt: main.o memory.o
	$(CC) -o $@ $^ $(CFLAGS) -L/usr/local/lib -lssl -lcrypto -lpthread -ldl
clean:
	rm -f *.o decrypt
