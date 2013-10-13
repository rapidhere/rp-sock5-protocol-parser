all: socks5

CC=gcc
FLAG=-O2 -Wall -Wextra

socks5: libsocks5.a socks5.h
	mkdir $@
	cp $^ $@
	rm -rf *.o
	rm libsocks5.a

libsocks5.a: socks5_common.o socks5_auth_meth.o socks5_connect.o socks5_data_convert.o
	ar cr $@ $^

test: testmain.c socks5.h libsocks5.a
	$(CC) -o test testmain.c -L. -lsocks5 $(FLAG)

socks5_common.o: socks5_common.c socks5.h
	$(CC) -c -o socks5_common.o socks5_common.c $(FLAG)

socks5_auth_meth.o: socks5_auth_meth.c socks5.h
	$(CC) -c -o socks5_auth_meth.o socks5_auth_meth.c $(FLAG)

socks5_connect.o: socks5_connect.c socks5.h
	$(CC) -c -o $@ socks5_connect.c $(FLAG)

socks5_data_convert.o : socks5_data_convert.c socks5.h
	$(CC) -c -o $@ socks5_data_convert.c $(FLAG)

clean:
	rm -rf *.o
