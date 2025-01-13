all: 
	gcc -o VPNclient VPNclient.c -lssl -lcrypto -lcrypt -lpthread
	gcc -std=gnu11 -o VPNserver VPNserver.c -lssl -lcrypto -lcrypt -lpthread

clean: 
	rm -f VPNclient VPNserver 
	rm -f *~

