all: victim.o
	cd ../netfilter; make
	gcc victim.o ../netfilter/netfilter.o -o victim -lnfnetlink -lnetfilter_queue -pthread -g

victim.o: victim.c
	gcc -I "../" -I "../netfilter" victim.c -c

clean:
	rm -f *~ victim