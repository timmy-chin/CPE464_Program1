trace: trace.c checksum.c
	gcc -o trace trace.c checksum.c

clean:
	rm trace