all: attacker_gateway.o
	cd ../netfilter; make
	gcc ../netfilter/netfilter.o attacker_gateway.o -o attacker_gateway -lnfnetlink -lnetfilter_queue -pthread -g


attacker_gateway.o: attacker_gateway.c 
	gcc -I "../netfilter" -I "../" attacker_gateway.c -pthread -c -g
clean:
	rm -f *~ attacker_gateway attacker_gateway.o