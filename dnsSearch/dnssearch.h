#ifndef DNSSEARCH_H_
#define DNSSEARCH_H_


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>


#define HOSTLEN   128
#define WORDLEN     50
#define DEFAULT_WORLDLIST "dnssrc.txt"
#define BOOL    unsigned char
#define TRUE    1
#define FALSE   0


typedef struct _dns_data_t {
    char host[128];
    char * host_addr;
    
} dnsdata_t;

typedef struct _dnsdata_v {
    dnsdata_t * dnsData;
    size_t size;
}dnsdata_v;

void nslookup (const int argc, char ** argv, dnsdata_v * dnsV);
void splash(void);
void nslookup_dump (dnsdata_v * dnsV);
int file_possible_len (FILE * fp); 

#endif /* DNSSEARCH_H_ */
