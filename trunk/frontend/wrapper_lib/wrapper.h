#ifndef __WRAPPER_LIB_H__
#define __WRAPPER_LIB_H__

struct app_request {
  uint16_t key_size;
  uint16_t iv_size;
  uint16_t msg_size;
  char *key;
  char *iv;
  char *msg;
  char *presp;
  void *callbk_tag;
};

struct app_response {
  uint16_t status;
};

typedef int (*frontend_queue_t)(struct app_request *app_req, 
		      		void *meta);


typedef void (*libcb_t) (void *callbk,
			 struct app_response *resp);


#endif
