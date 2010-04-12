#ifndef __WRAPPER_LIB_H__
#define __WRAPPER_LIB_H__


#define IXP_OP_3DES_ENCRYPT              0
#define IXP_OP_3DES_DECRYPT              1


struct des_hdr {
  uint16_t key_size;
  uint16_t iv_size;
  uint16_t msg_size;
};

typedef struct des_hdr des_hdr_t;

struct des_req {
  des_hdr_t *hdr;
  char *key;
  char *iv;
  char *msg;
  char *resp;
  void *cb;
};

typedef struct des_req des_req_t;

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
