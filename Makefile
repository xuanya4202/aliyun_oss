CC=gcc
CLFG= -g -fPIC
INC= -I /usr/include/libxml2
LIB=-lcrypto -lssl -L /usr/local/lib -lxml2
OUT=liboss.so
out:
	$(CC) $(CLFG) $(INC) -c oss_util.c -o oss_util.o
	$(CC) $(CLFG) $(INC) -c oss_init.c -o oss_init.o
	$(CC) $(CLFG) $(INC) -c oss_http_request.c -o oss_http_request.o
	$(CC) $(CLFG) $(INC) -c oss_http_response.c -o oss_http_response.o
	$(CC) $(CLFG) $(INC) -c oss_net.c -o oss_net.o
	$(CC) $(CLFG) $(INC) $(LIB) -shared oss_util.o oss_net.o oss_init.o oss_http_request.o oss_http_response.o  -o $(OUT)
clean:
	rm *.o -rf
	rm $(OUT)
