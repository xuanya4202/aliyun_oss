#include <stdio.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>  
#include <openssl/bio.h>  
#include <openssl/buffer.h> 
#include "oss_util.h"
#include "oss_net.h"
#include "oss_init.h"
#include "oss_http_request.h"
#include "oss_http_response.h"

int test_oss_put_bucket(oss_net_t *ossnet)
{
	int ret = 0 ;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "PUT");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/");
	ossreq.body = oss_strdup("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
						"<CreateBucketConfiguration >\r\n"
						"<LocationConstraint >oss-cn-beijing</LocationConstraint >\r\n"
						"</CreateBucketConfiguration >\r\n"
						);
	ossreq.body_len = strlen("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
						"<CreateBucketConfiguration >\r\n"
						"<LocationConstraint >oss-cn-beijing</LocationConstraint >\r\n"
						"</CreateBucketConfiguration >\r\n");
	
	ossreq.head_param = malloc(sizeof(char)*5*64);
	
	oss_snprintf(*ossreq.head_param[0], 64-1, "%s", "x-oss-acl:public-read");
	ossreq.head_param_len = 1;
	oss_create_request(ossnet, &ossreq);
	ossnet->call = NULL;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(200 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}
int test_oss_put_bucket_acl(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "PUT");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/?acl");
	
	ossreq.head_param = malloc(sizeof(char)*5*64);
	
	oss_snprintf(*ossreq.head_param[0], 64-1, "%s", "x-oss-acl:public-read-write");
	ossreq.head_param_len = 1;
	oss_create_request(ossnet, &ossreq);
	ossnet->call = NULL;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(200 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}

int test_oss_get_bucket_acl(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "GET");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/?acl");
	 
	oss_create_request(ossnet, &ossreq);
	ossnet->call = (void*)oss_get_bucket_acl;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(200 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}

int test_oss_get_bucket_location(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "GET");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/?location");
	 
	oss_create_request(ossnet, &ossreq);
	ossnet->call = (void*)oss_get_bucket_location;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(200 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}
int test_oss_delete_bucket(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "DELETE");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/");
	 
	oss_create_request(ossnet, &ossreq);
	ossnet->call = NULL;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(204 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}

int test_oss_put_object(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "PUT");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/hao");
	ossreq.body = oss_strdup("123456789");
	ossreq.body_len = strlen(ossreq.body);
	
	ossreq.head_param = malloc(sizeof(char)*5*64);
	
	oss_snprintf(*ossreq.head_param[0], 64-1, "%s", "x-oss-acl:public-read");
	ossreq.head_param_len = 1;
	oss_create_request(ossnet, &ossreq);
	ossnet->call = NULL;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(200 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}
int test_oss_get_object(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "GET");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/hao");
	 
	oss_create_request(ossnet, &ossreq);
	ossnet->call = (void*)oss_get_object;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(200 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}
int test_oss_delete_object(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "DELETE");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/hao");
	 
	oss_create_request(ossnet, &ossreq);
	ossnet->call = NULL;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(204 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}
int test_oss_get_object_acl(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "GET");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/hao?acl");
	 
	oss_create_request(ossnet, &ossreq);
	ossnet->call = (void*)oss_get_bucket_acl;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(200 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}
int test_oss_put_object_acl(oss_net_t *ossnet)
{
	int ret = 0;
	oss_req_param_t ossreq = {0};
	
	oss_snprintf(ossreq.bucket, sizeof(ossreq.bucket)-1, "%s", "hjl0123");
	oss_snprintf(ossreq.method, sizeof(ossreq.method)-1, "%s", "PUT");
	oss_snprintf(ossreq.method_param, sizeof(ossreq.method_param)-1, "%s", "/hao?acl");
	
	ossreq.head_param = malloc(sizeof(char)*5*64);
	
	oss_snprintf(*ossreq.head_param[0], 64-1, "%s", "x-oss-object-acl:public-read-write");
	ossreq.head_param_len = 1;
	oss_create_request(ossnet, &ossreq);
	ossnet->call = NULL;
	
	ret = http_connect(ossnet);
	if(0 != ret)
		return -1;
	oss_request_response(ossnet);
	//printf("status_code=%d result=%s\n", ossnet->status_code, ossnet->result);
	
	if(200 == ossnet->status_code)
	{
		printf("%s is ok\n", __FUNCTION__);
	}
	else
	{
		printf("%s is fail\n", __FUNCTION__);
	}
	ossnet->status_code = 0;
	oss_free(ossnet->result);
	oss_free(ossnet->request);
	oss_free(ossnet->response);
	http_done(ossnet);
	return 0;
}
static const char *access_key_id = "key id";
static const char *access_key_secret = "key secret";
int main(int argc, char *argv[])
{
	oss_net_t ossnet = {0};
	oss_so_init();
	ossnet.access_key_id = oss_strdup(access_key_id);
	ossnet.access_key_secret = oss_strdup(access_key_secret);
	oss_net_param_init(&ossnet, "oss-cn-beijing.aliyuncs.com", 443);
	
	test_oss_put_bucket(&ossnet);
	test_oss_put_bucket_acl(&ossnet);
	test_oss_get_bucket_acl(&ossnet);
	test_oss_get_bucket_location(&ossnet);
	test_oss_delete_bucket(&ossnet);
	
	test_oss_put_bucket(&ossnet);
	test_oss_put_bucket_acl(&ossnet);
	
	test_oss_put_object(&ossnet);
	test_oss_put_object_acl(&ossnet);
	test_oss_get_object_acl(&ossnet);
	test_oss_get_object(&ossnet);
	test_oss_delete_object(&ossnet);
	
	test_oss_delete_bucket(&ossnet);

	oss_free(ossnet.access_key_id);
	oss_free(ossnet.access_key_secret);
	return 0;	
}
