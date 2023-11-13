#include "dnssearch.h"

void splash(void) {
    printf("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|\n");
    printf("|-|-|-|-|-|-|-|-|-|-|-|.. DNSSEARCH v1.0 .. |-|-|-|-|-|-|-|-|-|-|-|-|-|\n");
    printf("|-|-|-|-|-|-|-|-| Uso: ./dnssearch alvo.com.br dnssrc.txt |-|-|-|-|-|-|-|\n");
    printf("|-|-|-|-|-|-|-|-|-| Mr-Zer00 -- Ethical Hacking -|-|-|-|--|-|-|-|-|-|\n");
    printf("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|\n");
}

int file_possible_len(FILE * fp) {
  	char c;
  	int lines = 0;
  	while (!feof(fp)) {
        c = fgetc(fp);
	  	if (c == 0x0a) {
		  	lines++;
		}
	}
    rewind(fp);
	return ++lines;
}

void 
nslookup (const int argc, char ** argv, dnsdata_v * dnsV) {
	char * result;
	FILE * dnssrc;
    char txt[50];
   	struct hostent * host;
    

    BOOL matched = FALSE;
    size_t i = 0;
    

    dnssrc = ( (argc < 3) ? fopen (DEFAULT_WORLDLIST, "r") : fopen (argv[2], "r") );
  	if (dnssrc == NULL) {
		fprintf (stderr, "[ERROR] - Opening the file: %s\n",
				 ( (argc < 3) ? DEFAULT_WORLDLIST : argv[2]) );
        exit (1);
	}

	dnsV->dnsData = (dnsdata_t *) calloc(file_possible_len (dnssrc), sizeof(dnsdata_t) );
    
	while(fscanf(dnssrc, "%s", &txt) != EOF) {
		result = (char *) strcat (txt,argv[1]);
		host=gethostbyname (result);
		if (host == NULL) {
			continue;
        } else {
            strncpy (dnsV->dnsData[i].host, result, HOSTLEN);
            dnsV->dnsData[i].host_addr = inet_ntoa ( *( (struct in_addr *)(host)->h_addr));
            matched = TRUE;
            i++;
        }
	}

    
    if (matched == FALSE) {
         free (dnsV->dnsData);
         dnsV->dnsData = NULL;
    } 
    dnsV->size = i;
}


void
nslookup_dump (dnsdata_v * dnsV) {
    dnsdata_t * t;
           
    if (dnsV->dnsData == NULL) {
        fprintf (stderr, "[WARN] - Got nothing [!!]\n");
        return;
    }
    size_t i;
 
    for (i = 0; i < dnsV->size; i++) {
        t = &(dnsV->dnsData[i]);
        printf("HOST ENCONTRADO: %s ====> IP: %s \n", (t->host), t->host_addr); 
    }
}
