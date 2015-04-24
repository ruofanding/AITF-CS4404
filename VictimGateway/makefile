all: victim_gateway.o
	gcc ../netfilter/netfilter.o victim_gateway.o -o victim_gateway -lnfnetlink -lnetfilter_queue -pthread

victim_gateway.o: victim_gateway.c
	gcc -I "../netfilter" -I "../" victim_gateway.c -pthread -c
clean:
	rm -f *~ victim_gateway