OPENSSL101=$(wildcard ~/.openssl/openssl-1.0.1u)
OPENSSL102=$(wildcard ~/.openssl/openssl-1.0.2o)
OPENSSL110=$(wildcard ~/.openssl/openssl-1.1.0h)
OPENSSL111=$(wildcard ~/.openssl/openssl-1.1.1-pre7)

X=$(wildcard ~/openssl/openssl-1.1.0h)
#X=$(wildcard ~/openssl/openssl-1.1.1-pre7)

OPENSSL=$(OPENSSL102)
OPENSSL_INC=-I$(OPENSSL)/include
#OPENSSL_INC=-I$(X) -I$(X)/include -I$(X)/ssl
OPENSSL_LIB=$(OPENSSL)/lib/libssl.a $(OPENSSL)/lib/libcrypto.a

OPENSSL_LIB_TRAVIS=/usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a
GCOV_CCFLAGS = -fprofile-arcs -ftest-coverage
GCOV_OUTPUT = *.gcda *.gcno *.gcov 

CC=gcc
CFLAGS=$(OPENSSL_INC) -g $(GCOV_CCFLAGS) -std=c99
DEPS=

all: decrypt

$(OPENSSL_INC):
	@echo "----------------------------------------------------------------------------"
	@echo "Please install OpenSSL or compliant library into ${OPENSSL}"
	@echo "----------------------------------------------------------------------------"
	@exit 1

demo: decrypt 
#	./decrypt samples/rsasnakeoil2.key samples/rsasnakeoil2-client samples/rsasnakeoil2-server
#	./decrypt samples/somin_tmp2k.pem samples/somin180614-client samples/somin180614-server
#	./decrypt samples/somin_tmp2k.pem samples/somin180620-client samples/somin180620-server
	./decrypt samples/somin_tmp2k.pem samples/c1 samples/s1 samples/c2 samples/s2 samples/c3 samples/s3 samples/c4 samples/s4


%.o: %c $(DEPS) $(OPENSSL_INC)
	$(CC) -c -o $@ $< $(CFLAGS)

decrypt: main.o memory.o ssl_stub.o util.o
	$(CC) -o $@ $^ $(CFLAGS) $(OPENSSL_LIB) -lpthread -ldl

travis-check: decrypt-check
	./decrypt-check samples/somin_tmp2k.pem samples/c1 samples/s1 samples/c2 samples/s2 samples/c3 samples/s3 samples/c4 samples/s4

decrypt-check: main.o memory.o ssl_stub.o util.o
	$(CC) -o $@ $^ $(CFLAGS) $(OPENSSL_LIB_TRAVIS) -lpthread -ldl

clean:
	rm -f *.o decrypt decrypt-check
