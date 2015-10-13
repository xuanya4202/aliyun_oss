#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "oss_util.h"
#include "oss_net.h"
#include "oss_init.h"


static char g_init = 0;

#ifdef OSS_HTTP_SSL

// Forward definitions for callback functions.
void ecos_locking_callback(int mode, int type, char *file, int line);
unsigned long ecos_thread_id_callback(void);

// Pointer to array of locks.
#ifdef WIN32
	static HANDLE  *lock_cs;
#else
	static pthread_mutex_t *lock_cs;
#endif
// This function allocates and initializes the lock array
// and registers the callbacks. This should be called
// after the OpenSSL library has been initialized and
// before any new threads are created.  
void thread_setup(void)
{
    int i;

    // Allocate lock array according to OpenSSL's requirements
#ifdef WIN32    
	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
#else
	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
#endif
    // Initialize the locks
    for (i = 0; i < CRYPTO_num_locks(); i++)
    {
#ifdef WIN32
		lock_cs[i] = CreateMutex(NULL, FALSE, NULL);
#else
		pthread_mutex_init(&(lock_cs[i]), NULL);
#endif
	}

    // Register callbacks
    CRYPTO_set_id_callback((unsigned long(*)())ecos_thread_id_callback);
    CRYPTO_set_locking_callback((void(*)())ecos_locking_callback);
}

// This function deallocates the lock array and deregisters the
// callbacks. It should be called after all threads have
// terminated.  
void thread_cleanup(void)
{
    int i;

    // Deregister locking callback. No real need to
    // deregister id callback.
    CRYPTO_set_locking_callback(NULL);

    // Destroy the locks
    for (i = 0; i < CRYPTO_num_locks(); i++)
    {
#ifdef WIN32
		CloseHandle(lock_cs[i]);
#else
		pthread_mutex_destroy(&(lock_cs[i]));
#endif
	}

    // Release the lock array.
    OPENSSL_free(lock_cs);
}

// Locking callback. The type, file and line arguments are
// ignored. The file and line may be used to identify the site of the
// call in the OpenSSL library for diagnostic purposes if required.
void ecos_locking_callback(int mode, int type, char *file, int line)
{
    if (mode & CRYPTO_LOCK)
    {
#ifdef WIN32
		WaitForSingleObject(lock_cs[type], INFINITE);
#else
		pthread_mutex_lock(&(lock_cs[type]));
#endif
	}
    else
    {
#ifdef WIN32
		ReleaseMutex(lock_cs[type]);
#else
		pthread_mutex_unlock(&(lock_cs[type]));
#endif
    }
}
// Thread id callback.
unsigned long ecos_thread_id_callback(void)
{
#ifdef WIN32
	return GetCurrentThreadId();
#else
	return (unsigned long)pthread_self();
#endif
}

/**
 *\fn        int oss_ssl_init()
 *\brief     初始化SSL
 *\return    int 0成功,其它失败
 */
int oss_ssl_init()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	thread_setup();
    return 0;
}

/**
 *\fn        int oss_ssl_uninit()
 *\brief     释放SSL
 *\return    int 0成功,其它失败
 */
int oss_ssl_uninit()
{
    if (g_init)
    {
        ERR_free_strings();
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        thread_cleanup();
        g_init = 0;
    }

    return 0;
}
#endif //OSS_HTTP_SSL

static int url_to_ip(const char *url, char *ip, int iplen)
{
	struct hostent *phost = NULL;
	if(NULL == url)
		return -1;
	phost = gethostbyname(url);
	
	if(NULL == phost)
		return -1;
	
	oss_inetntop(phost->h_addrtype, phost->h_addr_list[0], ip, iplen);
	return 0;
}


int oss_so_init()
{
#ifdef WIN32
	WORD sockVersion;
	WSADATA wsaData;
#endif
	
	if(0 != g_init)
		return 0;
	g_init = 1;

#ifdef WIN32
	sockVersion = MAKEWORD(2,2);
	wsaData;
	if(WSAStartup(sockVersion, &wsaData) != 0)
	{
		return -1;
	}
#endif

#ifdef OSS_HTTP_SSL
	oss_ssl_init();
#endif
	return 0;
}

int oss_net_param_init(oss_net_t *ossnet, char *url, int port)
{
	char ip[32] = {0};
	int len = 0;
	
	if(NULL == url || 0 == port)
	{
		oss_log_write("%s param url or port is null", __FUNCTION__);
		return -1;
	}
	len = 0;
	len = oss_snprintf(ossnet->url, 128-1, "%s", url);
	ossnet->url[len] = 0;
	url_to_ip(url, ip, sizeof(ip));
	len = oss_snprintf(ossnet->host, 32-1, "%s", ip);
	ossnet->host[len] = 0;
	ossnet->port = port;
	
	return 0;
}

static int http_get_body(oss_net_t *ossnet)
{
	char *p_start = NULL;
	char *p_end = NULL;
	char foundbody = 0;

	p_start = ossnet->response;
	p_end = strstr(p_start, "HTTP/1.1");
	if(NULL != p_end)
	{
		ossnet->status_code = atoi(p_end + 8);
	}
	p_start = NULL;
	p_end = NULL;
	
	p_start = ossnet->response;
	p_end = strstr(p_start, "\r\n");
	while(NULL != p_end)
	{
		if (p_end - p_start == 0)
		{
			p_start += 2;
			foundbody = 1;
			break;
		}
		p_start = p_end + 2;
		p_end = strstr(p_start, "\r\n");
	}
		
	if(foundbody)
	{
		ossnet->body = p_start;
	}
	
	return 0;
}

int oss_request_response(oss_net_t *ossnet)
{
	int ret = -1;
	//printf("send=%s\n", ossnet->request);
	ret = http_request_response(ossnet, ossnet->request, ossnet->request_len, &ossnet->response, &ossnet->response_len);
	//printf("recv=%s\n", ossnet->response);
	
	http_get_body(ossnet);
	if(NULL != ossnet->call && NULL != ossnet->body)
		ossnet->call(ossnet);
	return 0;
}