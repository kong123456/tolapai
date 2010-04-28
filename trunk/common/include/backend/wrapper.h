#ifndef __BACK_WRAPPER_LIB_H__
#define __BACK_WRAPPER_LIB_H__

struct app_request {
  uint16_t op;
  char *req_buf;
  char *presp;
  void *callbk_tag;
};


struct app_response {
  uint16_t status;
  char *presp;
};

typedef void (*libcb_t) (void *meta, void *callbk,
			 struct app_response *resp);

typedef struct app_request app_request_t;
typedef struct app_response app_response_t;

#endif
