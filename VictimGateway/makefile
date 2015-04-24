all: victim_gateway.o
	cd ../netfilter; make
	gcc ../netfilter/netfilter.o victim_gateway.o -o victim_gateway -lnfnetlink -lnetfilter_queue -pthread -g


victim_gateway.o: victim_gateway.c 
	gcc -I "../netfilter" -I "../" victim_gateway.c -pthread -c -g
clean:
	rm -f *~ victim_gateway victim_gateway.o