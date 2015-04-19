all: victim_gateway.c
	gcc -I "../" victim_gateway.c sniff.c -pthread -o victim_gateway -DINTERCEPT

clean:
	rm -f *~ victim_gateway