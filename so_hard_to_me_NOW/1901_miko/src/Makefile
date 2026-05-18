main: aes256.o bin_vec.o conv.o crypt.o gf.o matrix.o rng.o sha3.o consts.o main.o
	gcc -o main main.o aes256.o bin_vec.o conv.o crypt.o gf.o matrix.o rng.o sha3.o consts.o

main.o: main.c
	gcc -c main.c

aes256.o: aes256.c
	gcc -c aes256.c

bin_vec.o: bin_vec.c
	gcc -c bin_vec.c

conv.o: conv.c
	gcc -c conv.c

crypt.o: crypt.c
	gcc -c crypt.c

gf.o: gf.c	
	gcc -c gf.c

matrix.o: matrix.c	
	gcc -c matrix.c

rng.o: rng.c	
	gcc -c rng.c

sha3.o: sha3.c
	gcc -c sha3.c

consts.o: consts.c
	gcc -c consts.c

clean:
	rm -rf *.o