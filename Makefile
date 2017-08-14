all:
	gcc -Wall -o udp-scan udp-scan.c -lpthread

clean:
	rm -rf udp-scan *~

