LDLIBS=-lpcap

all: send-arp

main.o: main.cpp ethhdr.h arphdr.h ip.h mac.h

ip.o: ip.cpp ip.h

mac.o: mac.cpp mac.h

send-arp: main.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
