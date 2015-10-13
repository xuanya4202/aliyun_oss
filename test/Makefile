CC=gcc
CLFG= -g 
INC= -I ../
LIB=-lcrypto -lssl -L ../ -loss -Wl,-rpath ../
OUT=test
out:
	$(CC) $(CLFG) $(INC) -c main.c -o main.o
	$(CC) $(CLFG) $(LIB) $(INC) main.o -o $(OUT)
clean:
	rm *.o -rf
	rm $(OUT)
