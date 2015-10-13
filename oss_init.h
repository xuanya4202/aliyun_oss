#ifndef OSS_INIT_H_
#define OSS_INIT_H_
#include "oss_net.h"


int oss_so_init();
int oss_net_param_init(oss_net_t *ossnet, char *url, int port);

int oss_request_response(oss_net_t *ossnet);
#endif