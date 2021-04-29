#include "httpd.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "apr_tables.h"
#include "string.h"

static void register_hooks(apr_pool_t *pool);
static int multiCORS_handler(request_rec *r);
static int mcount(char *line);

//Data structure
typedef struct {
  char *domain;
} allowedDomains;

//Pool variable
static allowedDomains allowed_domains[128];

//Pool init
const char *multiCORS_set_domain(cmd_parms *cmd, void *cfg, const char *arg);

//directives setting
static const command_rec multiCORS_directives[] = {
  AP_INIT_TAKE1("Access-Control-Allow-Multi-Origin", multiCORS_set_domain, NULL, RSRC_CONF, "File to load"),
  {NULL}
};


//Register function
module AP_MODULE_DECLARE_DATA multiCORS_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  NULL,
  NULL,
  multiCORS_directives,
  register_hooks
};

//register_hooks: we force to run this module before mod_rewrite
static void register_hooks(apr_pool_t *pool){
  static const char * const aszSucc[] = {"mod_rewrite.c", NULL};
  ap_hook_fixups(multiCORS_handler, NULL, aszSucc, APR_HOOK_FIRST);
}

//multiCORS_handler: main function to be called on each request
static int multiCORS_handler(request_rec *r){
  int mci = 0;
  int isRef = 0;
  const char *ref;

  ref = apr_table_get(r->headers_in, "Referer");

  //If there's not referer, just end
  if(ref == NULL)
    return OK;

  //We will search among domain to see if referer is on the list
  while(isRef == 0 && mci < 128){
    if(allowed_domains[mci].domain == NULL)
      isRef = -1;
    else{
      if(strcmp(ref, allowed_domains[mci].domain) == 0)
        isRef = 1;
    }

    mci++;
  }

  //If isRef == 1 means that is an allowed server
  if(isRef == 1)
    apr_table_set(r->headers_out, "Access-Control-Allow-Origin", "*");

  return OK;
}

//This function will read "arg" (that may contain 1..128 valid origin-servers)
const char *multiCORS_set_domain(cmd_parms *cmd, void *cfg, const char *arg){
  FILE *msdr;
  FILE *msdw;
  ssize_t read;
  size_t len;
  char *line;
  int count = 0;
  int slen = 0;

  //Avoid parsing a empty file
  if(arg == NULL)
    return NULL;

  msdr = fopen(arg, "r");
  msdw = fopen("/var/log/apache2/multiCORS.log", "w");

  //If file cannot be open, end the function
  if(msdr == NULL)
    return NULL;

  if(msdw == NULL)
    return NULL;

  count = 0;
  line = NULL;
  fprintf(msdw, "Load phase starts\n");

  //"line" have each time a server to allow
  while((read = getline(&line, &len, msdr)) != -1 && count < 128){
    fprintf(msdw, "\tLine: %s", line);

    //search for exact path length
    slen = mcount(line);

    //allocate slen + 1 to allow \0
    allowed_domains[count].domain = malloc(sizeof(char) * slen + 1);
    memcpy(allowed_domains[count].domain, line, slen);
    allowed_domains[count].domain[slen] = '\0';

    count++;
  }

  fprintf(msdw, "\n\nLoad phase ends\n");

  //ensure that each unused domain is NULL
  for(;count < 128;count++)
    allowed_domains[count].domain = NULL;

  //clean memory before ending
  free(line);

  //close file
  fclose(msdr);

  fputs("multiCORS loaded successfully!\n", msdw);

  count = 0;

  while(count < 128 && allowed_domains[count].domain != NULL){
    fprintf(msdw, "[%i]: <%s>\n", count, allowed_domains[count].domain);
    count++;
  }

  fclose(msdw);

  return NULL;
}

static int mcount(char* line){
  int cnt = 0;

  while(line[cnt] != ' ' &&
        line[cnt] != '\n' &&
        line[cnt] != '\r')
    cnt++;

  return cnt;
}
