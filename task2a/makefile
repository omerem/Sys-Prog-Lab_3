all: do


do: virusDetector.o
	gcc -g -Wall -o do virusDetector.o


virusDetector.o: virusDetector.c
	gcc -g -Wall -c -o virusDetector.o virusDetector.c



.PHONY: clean

clean: 
	rm -f *.o do
