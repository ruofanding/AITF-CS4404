all: sniff.c client.c
	gcc sniff.c -o sniff -w
	gcc client.c -o client

clean:
	rm -f sniff client