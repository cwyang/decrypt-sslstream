decrypt-sslstream
===

Copyright (c) 2018 [Chul-Woong Yang](https://github.com/cwyang)

8 June 2018, cwyang

Decrypt captured SSL stream with given private key.

I used memory util of h2o(https://github.com/h2o/).

> usage:
>
>  $ decrypt key.pem raw-sslstream-from-client raw-sslstream-from-server
>
>  $ make demo
>


## sample run
<pre>
./decrypt samples/somin_tmp2k.pem samples/somin180620-client samples/somin180620-server

# SSL session decryptor
  by Chul-Woong Yang (cwyang@gmail.com)

->>  [TLS handshake] CLIENT_HELLO        len=94
->>  [TLS handshake] CLIENT_HELLO random: 82 b7 c2.. 
 <<- [TLS handshake] SERVER_HELLO        len=58
ver: 03 03
cip: 00 35
compr: 00
cipher: AES256-SHA
->>  [TLS handshake] CLIENT_KEY_EXCHANGE len=262
->>  [TLS handshake] CLIENT_KEY_EXCHANGE pms: 01 00 95.. 
pms decrypted:
0000: 03 03 61 3b 43 4e 94 06 ca 59 55 d8 29 8c 50 52   ..a;CN...YU.).PR
0010: d4 5d 8f 0d df fb d0 94 73 b7 78 1e 58 fc 8c 75   .]......s.x.X..u
0020: 1a 8a ce 5a e9 63 1a 51 d5 b3 3e 7e 61 da 69 de   ...Z.c.Q..>~a.i.
generate_ssl: TLS version 3.3
generate_ssl: master key[48]:
0000: 3c 24 2d e6 1a 55 4d 06 ed a1 dd ab 40 d5 a8 9d   <$-..UM.....@...
0010: 05 85 bd 45 cc 50 dd ef a5 9c 64 56 9b 76 63 d1   ...E.P....dV.vc.
0020: 1d 28 5e b6 7d 5d 15 67 51 1e 74 97 fb 5d 6b c6   .(^.}].gQ.t..]k.
generate_ssl: setup_key_block ok
generate_ssl: master key[48]:
0000: 3c 24 2d e6 1a 55 4d 06 ed a1 dd ab 40 d5 a8 9d   <$-..UM.....@...
0010: 05 85 bd 45 cc 50 dd ef a5 9c 64 56 9b 76 63 d1   ...E.P....dV.vc.
0020: 1d 28 5e b6 7d 5d 15 67 51 1e 74 97 fb 5d 6b c6   .(^.}].gQ.t..]k.
generate_ssl: setup_key_block ok
->>  [TLS record] change cipher spec     len=1
->>  [TLS record] encrypted handshake    len=64
_decrypt_record: buf_ptr = 0x257d0f0, buf_len=140
read_bio: buf_ptr = 0x257d0f0, buf_len= 140  |  16 03 03 00 40 ..
read_bio: buf_ptr = 0x257d0f0, buf_len= 135  |  93 8f 79 ba 6b ..
_decrypt_record: record[16]
0000: 14 00 00 0c bd 00 d1 0d bb 65 c6 6e ad 44 4e a7   .........e.n.DN.
->>  [TLS record] application data       len=48
_decrypt_record: buf_ptr = 0x257d0f0, buf_len=71
read_bio: buf_ptr = 0x257d0f0, buf_len=  71  |  17 03 03 00 30 ..
read_bio: buf_ptr = 0x257d0f0, buf_len=  66  |  7d 80 43 85 8f ..
_decrypt_record: record[11]
0000: 48 49 20 53 4f 4d 49 4e 21 21 0a                  HI SOMIN!!.
->>  [TLS record] alert                  len=48
 <<- [TLS handshake] CERTIFICATE         len=748
 <<- [TLS handshake] SERVER_HELLO_DONE   len=4
 <<- [TLS handshake] NEW_SESSION_TICKET  len=186
 <<- [TLS record] change cipher spec     len=1
 <<- [TLS record] encrypted handshake    len=64
_decrypt_record: buf_ptr = 0x2580130, buf_len=130
read_bio: buf_ptr = 0x2580130, buf_len= 130  |  16 03 03 00 40 ..
read_bio: buf_ptr = 0x2580130, buf_len= 125  |  ea 32 97 0b 65 ..
_decrypt_record: record[16]
0000: 14 00 00 0c 18 a4 45 0b e9 17 61 6c 3f c8 3b 77   ......E...al?.;w
 <<- [TLS record] application data       len=368
_decrypt_record: buf_ptr = 0x2580130, buf_len=373
read_bio: buf_ptr = 0x2580130, buf_len= 373  |  17 03 03 01 70 ..
read_bio: buf_ptr = 0x2580130, buf_len= 368  |  b4 f7 c3 5a 71 ..
_decrypt_record: record[325]
0000: 48 54 54 50 2f 31 2e 31 20 34 30 30 20 42 61 64   HTTP/1.1 400 Bad
0010: 20 52 65 71 75 65 73 74 0d 0a 53 65 72 76 65 72    Request..Server
0020: 3a 20 6e 67 69 6e 78 2f 31 2e 31 32 2e 32 0d 0a   : nginx/1.12.2..
0030: 44 61 74 65 3a 20 57 65 64 2c 20 32 30 20 4a 75   Date: Wed, 20 Ju
0040: 6e 20 32 30 31 38 20 30 32 3a 32 38 3a 35 35 20   n 2018 02:28:55 
0050: 47 4d 54 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70   GMT..Content-Typ
0060: 65 3a 20 74 65 78 74 2f 68 74 6d 6c 0d 0a 43 6f   e: text/html..Co
0070: 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 31 37   ntent-Length: 17
0080: 33 0d 0a 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63   3..Connection: c
0090: 6c 6f 73 65 0d 0a 0d 0a 3c 68 74 6d 6c 3e 0d 0a   lose....<html>..
00a0: 3c 68 65 61 64 3e 3c 74 69 74 6c 65 3e 34 30 30   <head><title>400
00b0: 20 42 61 64 20 52 65 71 75 65 73 74 3c 2f 74 69    Bad Request</ti
00c0: 74 6c 65 3e 3c 2f 68 65 61 64 3e 0d 0a 3c 62 6f   tle></head>..<bo
00d0: 64 79 20 62 67 63 6f 6c 6f 72 3d 22 77 68 69 74   dy bgcolor="whit
00e0: 65 22 3e 0d 0a 3c 63 65 6e 74 65 72 3e 3c 68 31   e">..<center><h1
00f0: 3e 34 30 30 20 42 61 64 20 52 65 71 75 65 73 74   >400 Bad Request
0100: 3c 2f 68 31 3e 3c 2f 63 65 6e 74 65 72 3e 0d 0a   </h1></center>..
0110: 3c 68 72 3e 3c 63 65 6e 74 65 72 3e 6e 67 69 6e   <hr><center>ngin
0120: 78 2f 31 2e 31 32 2e 32 3c 2f 63 65 6e 74 65 72   x/1.12.2</center
0130: 3e 0d 0a 3c 2f 62 6f 64 79 3e 0d 0a 3c 2f 68 74   >..</body>..</ht
0140: 6d 6c 3e 0d 0a                                    ml>..
</pre>
