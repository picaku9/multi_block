all : multi_block_loop

multi_block_loop: main.o
	g++ -g -o multi_block_loop main.o -lnetfilter_queue

main.o:
	gcc -g -c -o main.o nfqnl_test.c -lnetfilter_queue

clean:
	rm -f multi_block_loop
	rm -f *.o
