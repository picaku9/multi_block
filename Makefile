all : multi_block

multi_block: radix.o main.o
	g++ -g -o multi_block main.o radix.o -l netfilter_queue

radix.o: radix.cpp radix.h
	g++ -c -o radix.o radix.cpp

main.o: multi_block.cpp radix.h
	g++ -c -o main.o multi_block.cpp -lnetfilter_queue

clean:
	rm -f multi_block
	rm -f *.o