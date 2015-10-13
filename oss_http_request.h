#ifndef OSS_HTTP_REQUEST_H_
#define OSS_HTTP_REQUEST_H_

typedef struct oss_req_param_s oss_req_param_t;
struct oss_req_param_s
{
	char method[12];
	char method_param[64];
	char bucket[64];
	char *body;
	size_t body_len;
	char (*head_param)[5][64];
	int head_param_len; //头参数个数
};


int oss_create_request(oss_net_t *ossnet, oss_req_param_t *ossreq);
#endif
