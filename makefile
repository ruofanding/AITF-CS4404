sniff_test: sniff_test.c sniff.o
	gcc -c sniff_test.c
	gcc sniff_test.o sniff.o -o sniff_test

sniff: sniff.c sniff.h
	gcc -c sniff.c 
clean:
	rm -f sniff_test client *.o *~