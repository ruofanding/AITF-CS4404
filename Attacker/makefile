all: attacker.o
	cd ../netfilter; make
	gcc ../netfilter/netfilter.o attacker.o -o attacker -lnfnetlink -lnetfilter_queue -pthread -g


attacker.o: attacker.c 
	gcc -I "../netfilter" -I "../" attacker.c -pthread -c -g
clean:
	rm -f *~ attacker attacker.o