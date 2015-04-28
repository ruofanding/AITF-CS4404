all: netfilter.c netfilter.h
	gcc -c netfilter.c -lnfnetlink -lnetfilter_queue -I "../" -g -pthread
clean:
	rm -f netfilter netfilter.o