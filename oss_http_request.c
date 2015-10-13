#include <stdio.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>  
#include <openssl/bio.h>  
#include <openssl/buffer.h> 
#include <sys/types.h>
#include "oss_net.h"
#include "oss_http_request.h"

char *date_gmt(char *gmt, int gmt_len)
{
	time_t t;
	t = time(NULL);
	
	strftime(gmt, gmt_len, "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
	return gmt;
}
static int base64_encode(char *str,int str_len,char *encode,int encode_len)
{
      BIO *bmem,*b64;
      BUF_MEM *bptr;
      b64=BIO_new(BIO_f_base64());
      bmem=BIO_new(BIO_s_mem());
      b64=BIO_push(b64,bmem);
      BIO_write(b64,str,str_len); //encode
      BIO_flush(b64);
      BIO_get_mem_ptr(b64,&bptr);
     if(bptr->length>encode_len){
         oss_log_write("encode_len too small\n");
         return -1; 
     }   
     encode_len=bptr->length;
     memcpy(encode,bptr->data,bptr->length);
 //  write(1,encode,bptr->length);
     BIO_free_all(b64);
     return encode_len;
}
static int hmac_sha1_encode(const char *key, const char *input, char *output, int *output_len)
{
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
	HMAC_Update(&ctx, input, strlen(input));
	HMAC_Final(&ctx, output, output_len);
	HMAC_CTX_cleanup(&ctx);
	return *output;
}
int oss_create_authorization(const char *access_key_secret, const char*bucket, const char*method, const char *method_param, const char*oss_x, const char *oss_date, char *out, int out_len)
{
	char auth_info[1024] = {0};
	char hmac_value[512] = {0};
	int hmac_len = 0;
	char base64_value[512] = {0};
	int len = 0;
	if(NULL == access_key_secret || 
		NULL == bucket || 
		NULL == method || 
		NULL == method_param || 
		NULL == oss_date)
	{
		return -1;	
	}
	
	if(0 == oss_x[0])
	{
		oss_snprintf(auth_info, sizeof(auth_info)-1, "%s\n\n\n%s\n/%s%s", method, oss_date, bucket, method_param);
	}
	else
	{
		oss_snprintf(auth_info, sizeof(auth_info)-1, "%s\n\n\n%s\n%s/%s%s", method, oss_date, oss_x, bucket, method_param);
	}
	hmac_sha1_encode(access_key_secret, auth_info, hmac_value, &hmac_len);
	len = base64_encode(hmac_value, hmac_len, out, out_len);
	out[len-1] = 0;
	return len;
}

const static char *GET_SERVICE="%s %s HTTP/1.1\r\n"
							"Date: %s\r\n"
							"Host: %s.%s\r\n"
							"Authorization: OSS %s:%s\r\n";
							
int oss_create_request(oss_net_t *ossnet, oss_req_param_t *ossreq)
{
	char head_value[1024] = {0};
	char *recv_value = NULL;
	int recv_len = 0;
	char authorization[128] = {0};
	char oss_date[64] = {0};
	char x_oss[128] = {0};
	int i = 0;
	int len = 0;
	
	for(i=0; i < ossreq->head_param_len; ++i)
	{
		if(strstr(*ossreq->head_param[i], "x-oss"))
		{
			strcat(x_oss, *ossreq->head_param[i]);
			strcat(x_oss, "\n");
		}
	}
	
	date_gmt(oss_date, sizeof(oss_date));
	
	oss_create_authorization(ossnet->access_key_secret, ossreq->bucket, ossreq->method, ossreq->method_param, 
								x_oss, oss_date, authorization, sizeof(authorization));
	len = 0;
	len = oss_snprintf(head_value, sizeof(head_value)-1, GET_SERVICE, ossreq->method, ossreq->method_param, oss_date, 
			ossreq->bucket, ossnet->url, ossnet->access_key_id, authorization);
	
	head_value[len] = 0;
	
	for(i=0; i < ossreq->head_param_len; ++i)
	{
		strcat(head_value, *ossreq->head_param[i]);
		strcat(head_value, "\r\n");
		len+=strlen(*ossreq->head_param[i]);
		len+=2;
	}
	
	if(ossreq->body != NULL)
	{
		char content_len[64] = {0};
		len+=oss_snprintf(content_len, sizeof(content_len)-1, "Content-Length:%Iu", ossreq->body_len);	
		strcat(head_value, content_len);
		strcat(head_value, "\r\n");
		len+=2;
	}
	strcat(head_value, "\r\n");
	len+=2;
	head_value[len] = 0;
	
	
	ossnet->request = (char *)malloc(len+2+ossreq->body_len);
	if(ossreq->body != NULL)
	{	
		len = oss_snprintf(ossnet->request, len+ossreq->body_len+1, "%s%s", head_value, ossreq->body);
	}
	else
	{
		len = oss_snprintf(ossnet->request, len+1, "%s", head_value);
	}
	//memcpy(ossnet->request, send_value, len);
	ossnet->request[len] = 0;
	ossnet->request_len = len;
	return 0;
}