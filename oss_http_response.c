#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include "oss_util.h"
#include "oss_net.h"
#include "oss_init.h"
#include "oss_http_response.h"

xmlXPathObjectPtr get_nodeset(xmlDocPtr doc, xmlChar *xpath)
{
    xmlXPathContextPtr context;
    xmlXPathObjectPtr result;

    context = xmlXPathNewContext(doc);
    if(NULL == context) {
        oss_log_write("Error in xmlXPathNewContent\n");
        return NULL;
    }

    result = xmlXPathEvalExpression(xpath, context);
    xmlXPathFreeContext(context);
    if(NULL == result) {
        oss_log_write("Error in xmlXPathEvalExpression\n");
        return NULL;
    }

    if(xmlXPathNodeSetIsEmpty(result->nodesetval)) {
        xmlXPathFreeObject(result);
        return NULL;
    }

    return result;
}

char *get_xmlnode_value(char **p, xmlDocPtr doc, const char *xml_path)
{
    char *value = NULL;
    xmlChar *xpath;
    xmlXPathObjectPtr result;
    xmlNodeSetPtr nodeset;
    xmlNodePtr cur_node;
    xmlChar *node_content;

    xpath = (xmlChar*) xml_path;
    result = get_nodeset(doc, xpath);

    if(result) {
        nodeset = result->nodesetval;
        cur_node = nodeset->nodeTab[0]->xmlChildrenNode;
        node_content = xmlNodeGetContent(cur_node);
        *p = oss_strdup((char *)node_content);
        xmlFree(node_content);
        xmlXPathFreeObject(result);
    }
    
    return *p;
}

int oss_get_bucket_acl(oss_net_t *ossnet)
{
	char *value = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL;
	char xpath[] = "/AccessControlPolicy/AccessControlList/Grant";
	
	if(NULL == ossnet->body)
		return -1;
	
	doc = xmlParseMemory(ossnet->body, strlen(ossnet->body));
	if(NULL == doc)
		return -1;
	
    cur = xmlDocGetRootElement(doc);//获取根节点

	value = get_xmlnode_value((char **)&ossnet->result, doc, xpath);
	
	return (NULL == value?-1:0);
}

int oss_get_bucket_location(oss_net_t *ossnet)
{
	char *value = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL;
	char xpath[] = "/LocationConstraint";
	
	if(NULL == ossnet->body)
		return -1;
	
	doc = xmlParseMemory(ossnet->body, strlen(ossnet->body));
	if(NULL == doc)
		return -1;
	
    cur = xmlDocGetRootElement(doc);//获取根节点

	value = get_xmlnode_value((char **)&ossnet->result, doc, xpath);
	
	return (NULL == value?-1:0);
}

int oss_get_object(oss_net_t *ossnet)
{
	if(NULL == ossnet->body)
		return -1;
	*(char **)&ossnet->result = oss_strdup(ossnet->body);
	return 0;
}