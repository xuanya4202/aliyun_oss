#ifndef OSS_UTIL_H_
#define OSS_UTIL_H_
#include "oss_config.h"

#if defined (WIN32) || defined (__MINGW32__)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Ws2tcpip.h>
#define OSS_SOCKET SOCKET
#define oss_closesocket(n) closesocket(n)
#define oss_snprintf _snprintf
#define oss_strcasecmp stricmp
#define oss_strdup _strdup
#define oss_sleep(N) Sleep(1000*(N))
#define oss_inetntop InetNtop
#else
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#define OSS_SOCKET int
#define oss_closesocket(n) close(n)
#define oss_snprintf snprintf
#define oss_sleep(N) sleep(N)
#define oss_strcasecmp strcasecmp
#define oss_strdup strdup
#define oss_inetntop inet_ntop
#endif //WIN32

//#ifdef OSS_HTTP_SSL
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
//#endif //OSS_HTTP_SSL

#define oss_log_write printf
#define oss_free(s) do{if(NULL != s){free(s); s = NULL;}}while(0)


typedef struct oss_net_s oss_net_t;

struct oss_net_s{
	OSS_SOCKET sockfd;
	int port;
	char host[32];
	int error;
	int errmode;
	int errnum;
	int recv_timeout;
	char *access_key_id;
	char *access_key_secret;
	char url[128];
	char *request;
	int request_len;
	char *response;
	int response_len;
	int status_code;
	char *body;
	void *result;
	
	void *(*call)();
	
#ifdef OSS_HTTP_SSL
	SSL_CTX *ctx;
    SSL *ssl;
#endif /*OSS_HTTP_SSL*/
};

#endif