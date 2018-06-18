OPENSSL101=$(wildcard ~/.openssl/openssl-1.0.1u)
OPENSSL102=$(wildcard ~/.openssl/openssl-1.0.2o)
OPENSSL110=$(wildcard ~/.openssl/openssl-1.1.0h)
OPENSSL111=$(wildcard ~/.openssl/openssl-1.1.1-pre7)

OPENSSL=$(OPENSSL101)
OPENSSL_INC=$(OPENSSL)/include
OPENSSL_LIB=$(OPENSSL)/lib/libssl.a $(OPENSSL)/lib/libcrypto.a

CC=gcc
CFLAGS=-I$(OPENSSL_INC) -g
DEPS=

all: decrypt

$(OPENSSL_INC):
	@echo "----------------------------------------------------------------------------"
	@echo "Please install OpenSSL or compliant library into ${OPENSSL}"
	@echo "----------------------------------------------------------------------------"
	@exit 1

demo: decrypt 
#	./decrypt samples/rsasnakeoil2.key samples/rsasnakeoil2-client samples/rsasnakeoil2-server
	./decrypt samples/somin_tmp2k.pem samples/somin180614-client samples/somin180614-server

%.o: %c $(DEPS) $(OPENSSL_INC)
	$(CC) -c -o $@ $< $(CFLAGS)

decrypt: main.o memory.o ssl_stub.o
	$(CC) -o $@ $^ $(CFLAGS) $(OPENSSL_LIB) -lpthread -ldl
clean:
	rm -f *.o decrypt
