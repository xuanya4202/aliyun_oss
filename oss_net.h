#ifndef OSS_NET_
#define OSS_NET_

#include "oss_util.h"
#include "oss_config.h"


#define TCP_SELECT_RCV 0x1
#define TCP_SELECT_SND 0x2
#define TCP_SELECT_ERR 0x4
#define TCP_SELECT_ALL 0x7



int http_done(oss_net_t *ossnet);
int http_connect(oss_net_t *ossnet);
int http_request_response(oss_net_t *ossnet, const char *send, int send_len, char **recv, int *recv_len);

#endif //OSS_NET_H_

