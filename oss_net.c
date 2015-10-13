#include "oss_util.h"
#include "oss_init.h"
#include "oss_config.h"
#include "oss_net.h"

static void show_certs(SSL* ssl);
static int base64_encode(char *str,int str_len,char *encode,int encode_len);

 int hex_to_int(char s[])
{
    int i,m,temp=0,n;
    m = strlen(s);
    for(i=0; i < m; i++)
    {
        if(s[i]>='A' && s[i] <= 'F')
            n = s[i] - 'A' + 10;
        else if(s[i] >='a' && s[i] <= 'f')
            n = s[i] - 'a' + 10;
        else if(s[i] >='0' && s[i] <= '9')
            n = s[i]-'0';
        else
            return 0;
        temp = temp*16 + n;
    }
    return temp;
}
/******************************************************************************/
int http_connect(oss_net_t *ossnet)
{
	int ret = -1;
	struct sockaddr_in addr;
    struct timeval timeo = {OSS_HTTP_RECV_TIMEOUT, 0};
	int timeout = 0;

	ossnet->sockfd = socket(PF_INET, SOCK_STREAM, 0);
#ifdef WIN32
	 timeout = 1000*OSS_HTTP_RECV_TIMEOUT;
	setsockopt(ossnet->sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(int));
	setsockopt(ossnet->sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(int));
#else
    setsockopt(ossnet->sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeo, sizeof(timeo));
	setsockopt(ossnet->sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeo, sizeof(timeo));
#endif
	memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ossnet->port);
    addr.sin_addr.s_addr = inet_addr(ossnet->host);
#ifdef WIN32    
    if(connect(ossnet->sockfd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
#else
	if(connect(ossnet->sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
#endif
    {
        oss_closesocket(ossnet->sockfd);
		//cout<< "failed to connect" << ossnet->host<< ossnet->port<< errno<<endl;
        return -1;
    }
#ifdef OSS_HTTP_SSL
    ossnet->ctx = SSL_CTX_new(SSLv23_client_method());
    if(ossnet->ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        //char error[128];
        //snprintf(error, sizeof(error) - 1, "failed to create SSL_CTX %s", stderr);
        //cout<<error<<endl;
        oss_closesocket(ossnet->sockfd);
        return -1;
    }

    ossnet->ssl = SSL_new(ossnet->ctx);
    SSL_set_fd(ossnet->ssl, ossnet->sockfd);
    ret = SSL_connect(ossnet->ssl);
    if(ret != 1)
    {
        //lim_write_log(LOG_LEVEL_WARN, "failed to bind ssl on socket, code[%d]", SSL_get_error(ossnet->ssl, ret));
        SSL_free(ossnet->ssl);
        oss_closesocket(ossnet->sockfd);
        SSL_CTX_free(ossnet->ctx);
        return -1;
    }
    show_certs(ossnet->ssl);
#endif
    return 0;
}

static void show_certs(SSL* ssl)
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    if( cert != NULL )
    {
        char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        OPENSSL_free(line);
        X509_free(cert);
    }
    else
        oss_log_write("No certificates.");
}

int http_done(oss_net_t *ossnet)
{
	if (NULL == ossnet)
        return 0;
#ifdef OSS_HTTP_SSL
    if (NULL != ossnet->ssl)
        SSL_free(ossnet->ssl);
    
    if (NULL != ossnet->ctx)
        SSL_CTX_free(ossnet->ctx);
#endif

    if (ossnet->sockfd > 2)
        oss_closesocket(ossnet->sockfd);
	return 0;
}


static int http_send(oss_net_t *ossnet, const char *s, int len)
{ 
	int ret = 0;
#ifdef OSS_HTTP_SSL
	if (ossnet->ssl)
        ret = SSL_write(ossnet->ssl, s, len);
#else
	ret = send(ossnet->sockfd, s, len, 0);
#endif
	return ret;
}

/******************************************************************************/
static size_t http_recv(oss_net_t *ossnet, char *s, size_t n)
{  
	int r;
	int retries = 2; /* max 2 */
	
#ifdef OSS_HTTP_SSL
	int err = 0;
	for(;;)
	{
		if(ossnet->ssl)
		{ 
			r = SSL_read(ossnet->ssl, s, (int)n);
			if (r > 0)
			  return (size_t)r;
			err = SSL_get_error(ossnet->ssl, r);
			if (err != SSL_ERROR_NONE && err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
			  return 0;
		}
      
      	if (retries-- <= 0)
        	return 0;
	}
#else
	r = recv(ossnet->sockfd, s, n, 0);
#endif
	if (r >= 0)
		return (size_t)r;
	return 0;
}

int http_request_response(oss_net_t *ossnet, const char *send, int send_len, char **recv, int *recv_len)
{
	char temp[OSS_HTTP_RECV_BUF_MAX] = {0};
	int len = -1;
	char *buf = NULL;
	char *p_start = NULL;
    char *p_end = NULL;
	int total_len = 0;
	int foundbody = 0;
	int boby_len = 0;
	int flag = 1;
	char *temp1 = NULL;
	char tmp[8] = {0};
	int chunk_size = 0;
	int chunk_len  = 0;
	int recv_chunk_len = 0;
	int tem_len = 0;
	
	len = http_send(ossnet, send,  send_len);
	if(len <= 0)
		return len;
	
	buf = (char *)malloc(1);
	total_len = 0;
	for(;0 == foundbody;)
	{
		len = http_recv(ossnet, temp, sizeof(temp)-1);
		if(len <= 0)
			return len;
		temp[len] = 0;
			
		buf = (char *)realloc(buf,total_len+len+1);
		memcpy(&buf[total_len], temp, len);
		total_len += len;
		buf[total_len] = 0;
		
		p_start = buf;
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
	}
	
	if(NULL != p_start)
	{
		boby_len = strlen(p_start);
	}
	
	if(NULL != strstr(buf,"Transfer-Encoding: chunked"))
	{
		p_start = buf;
		p_end = strstr(p_start, "\r\n");
			while(NULL != p_end)
			{
				if (p_end - p_start == 0)
				{
					p_start += 2;
					//foundbody = true;
					break;
				}
				p_start = p_end + 2;
				p_end = strstr(p_start, "\r\n");
			}
	
		
		p_end = strstr(p_start, "\r\n");
		strncpy(tmp, p_start, p_end - p_start);
		tmp[p_end - p_start] = 0;

		total_len-=(strlen(tmp)+2);
		while(1)
		{
			chunk_size = hex_to_int(tmp);
			
			if(1 == flag)
			{
				chunk_size = chunk_size - boby_len;
				flag = 0;
			}
			if(0 == chunk_size)
				break;

			if(temp1 != NULL)
			{
				free(temp1);
				temp1 = NULL;
			}
			temp1 = (char *)malloc(chunk_size);
			len = 0;
			chunk_len = chunk_size;
		
			recv_chunk_len = 0;
			while(recv_chunk_len != chunk_size)
			{
				chunk_len -= len;
				len = http_recv(ossnet, &temp1[recv_chunk_len], chunk_len);
				if(len <= 0)
				{
					if(NULL != buf)
					{
						free(buf);
						buf = NULL;
					}
					return len;
				}
				recv_chunk_len+=len;
			}
	
			buf = (char *)realloc(buf,total_len+recv_chunk_len+1);
			memcpy(&buf[total_len-1], temp1, recv_chunk_len);
			total_len += recv_chunk_len;
			buf[total_len] = 0;

			if(NULL != temp1)
			{
				free(temp1);
				temp1 = NULL;
			}

			memset(temp, 0, sizeof(temp));
			tem_len = 0;
			len = http_recv(ossnet, temp, 1);/*\r\n*/
			if(len <= 0)
			{
				if(NULL != buf)
				{
					free(buf);
					buf = NULL;
				}
				return len;
			}
			len = http_recv(ossnet, temp, 1);/*\r\n*/
			if(len <= 0)
			{
				if(NULL != buf)
				{
					free(buf);
					buf = NULL;
				}
				return len;
			}
			while(1)
			{
				len = http_recv(ossnet, temp, 1);
				if(len <= 0)
				{
					if(NULL != buf)
					{
						free(buf);
						buf = NULL;
					}
					return len;
				}
				if('\r' == temp[0])
				{
					len = http_recv(ossnet, temp, 1);
					break;
				}
				memcpy(&tmp[tem_len-1], temp, len);
				tem_len += len;
			}
			tmp[tem_len] = 0;
		}
	}
	else if(NULL != (p_start = strstr(buf, "Content-Length:")))
	{
		if(NULL != (p_end  = strstr(p_start, "\r\n")))
		{
			
			p_end = strstr(p_start, "\r\n");
			strncpy(tmp, &p_start[strlen("Content-Length:")], p_end - (p_start+strlen("Content-Length:")));
			tmp[p_end - (p_start+strlen("Content-Length:"))] = 0;

			chunk_size = atoi(tmp);
			
			if(chunk_size > boby_len)
			{
				chunk_size = chunk_size - boby_len;
				if(0 != chunk_size)
				{
					char *temp1 = (char *)malloc(chunk_size);
					len = 0;
					chunk_len = chunk_size;
			
					recv_chunk_len = 0;
					while(recv_chunk_len != chunk_size)
					{
						chunk_len -= len;
						len = http_recv(ossnet, &temp1[recv_chunk_len], chunk_len);
						if(len <= 0)
						{
							if(NULL != buf)
							{
								free(buf);
								buf = NULL;
							}
							return len;
						}
						recv_chunk_len+=len;
					}

					buf = (char *)realloc(buf,total_len+recv_chunk_len+1);
					memcpy(&buf[total_len], temp1, recv_chunk_len);
					total_len += recv_chunk_len;
					//total_len-=;
					buf[total_len] = 0;
					if(NULL != temp1)
					{
						free(temp1);
						temp1 = NULL;
					}
				}
			}
			else
			{
				total_len-= boby_len;
				buf[total_len] = 0;
			}
		}
		
	}

	if(len > 0)
	{
		*recv = buf;
		*recv_len = total_len;
		//len = 0;
	}
	return len;
}