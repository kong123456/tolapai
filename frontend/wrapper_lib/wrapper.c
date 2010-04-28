/*  
 *   Tolapai DomU Wrapper Library 
 *   Author: Venkat (venkatraghavan@gatech.edu)
*/

/* kernel includes */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

/* tolapai crypto drive includes */
#include <cpa_cy_sym.h>
#include <cpa_cy_im.h>
#include <cpa_sample_utils.h>

#include <frontend/wrapper.h>

#define IXP_RSP_OKAY 0 

struct sess_ctx {
  CpaCySymCipherSetupData *cipher_data;
  CpaCySymCbFunc pSymCb;  
};

typedef struct sess_ctx sess_ctx_t;

struct local_req {
  CpaCySymOpData *symop;
  CpaBufferList *src_bufflist;
  CpaBufferList *dest_bufflist;
  void *callback_tag;
};

typedef struct local_req local_req_t;

struct wrap_lib {
  void *drv_meta;
  frontend_queue_t fn_queue_request;
  int is_ready;
} glob_info;


CpaStatus
cpaCySymSessionCtxGetSize(const CpaInstanceHandle instanceHandle,
        		  const CpaCySymSessionSetupData *pSessionSetupData,
        		  Cpa32U *pSessionCtxSizeInBytes) {

  *pSessionCtxSizeInBytes = sizeof(struct sess_ctx);

  return CPA_STATUS_SUCCESS;
}

EXPORT_SYMBOL(cpaCySymSessionCtxGetSize);

CpaStatus 
cpaCyBufferListGetMetaSize(const CpaInstanceHandle instanceHandle,
        		   Cpa32U numBuffers,
        		   Cpa32U *pSizeInBytes) {
  *pSizeInBytes = sizeof(local_req_t);

  return CPA_STATUS_SUCCESS;
}

EXPORT_SYMBOL(cpaCyBufferListGetMetaSize);

static void
set_cipher_data(struct sess_ctx *s_ctx, 
		const CpaCySymSessionSetupData *psessdata) {

  CpaStatus status = CPA_STATUS_SUCCESS;

  status = OS_MALLOC(&s_ctx->cipher_data, sizeof(CpaCySymCipherSetupData));

  if(status != CPA_STATUS_SUCCESS) {
    printk(KERN_ERR "Error allocating ciphersetupdata\n");
    return;
  }

  status = OS_MALLOC(&s_ctx->cipher_data->pCipherKey, psessdata->cipherSetupData.cipherKeyLenInBytes);
  
  if(status != CPA_STATUS_SUCCESS) {
    printk(KERN_ERR "Error allocating cipherkey\n");
    return;
  }

  s_ctx->cipher_data->cipherAlgorithm = psessdata->cipherSetupData.cipherAlgorithm; 

  s_ctx->cipher_data->cipherKeyLenInBytes = psessdata->cipherSetupData.cipherKeyLenInBytes;
  
  s_ctx->cipher_data->cipherDirection = psessdata->cipherSetupData.cipherDirection;

  memcpy(s_ctx->cipher_data->pCipherKey, psessdata->cipherSetupData.pCipherKey, psessdata->cipherSetupData.cipherKeyLenInBytes);

  return;

}

CpaStatus
cpaCySymInitSession(const CpaInstanceHandle instanceHandle,
        const CpaCySymCbFunc pSymCb,
        const CpaCySymSessionSetupData *pSessionSetupData,
        CpaCySymSessionCtx pSessionCtx) {
 
  struct sess_ctx *s_ctx = (struct sess_ctx *)pSessionCtx;

  if(!glob_info.is_ready) {
    return CPA_STATUS_FAIL;
  }
 
  set_cipher_data(pSessionCtx, pSessionSetupData);
  s_ctx->pSymCb = pSymCb;

  return CPA_STATUS_SUCCESS;
}

EXPORT_SYMBOL(cpaCySymInitSession);

CpaStatus
cpaCySymRemoveSession(const CpaInstanceHandle instanceHandle,
        	      CpaCySymSessionCtx pSessionCtx) {
  
  struct sess_ctx *s_ctx = (struct sess_ctx *)pSessionCtx;

  if(s_ctx->cipher_data->pCipherKey != NULL) {
     OS_FREE(s_ctx->cipher_data->pCipherKey);
     s_ctx->cipher_data->pCipherKey = NULL;
  }

  if(s_ctx->cipher_data != NULL) {
    OS_FREE(s_ctx->cipher_data);
    s_ctx->cipher_data = NULL;
  }    

  return CPA_STATUS_SUCCESS;
}

EXPORT_SYMBOL(cpaCySymRemoveSession);

CpaStatus
cpaCySymPerformOp(const CpaInstanceHandle instanceHandle,
		  void *pCallbackTag,
		  const CpaCySymOpData *pOpData,
		  const CpaBufferList *pSrcBuffer,
		  CpaBufferList *pDstBuffer,
		  CpaBoolean *pVerifyResult) {

  local_req_t *lreq = NULL;
  struct sess_ctx *s_ctx = pOpData->pSessionCtx;
  struct app_request app_req;
 
  lreq = (local_req_t *) pSrcBuffer->pPrivateMetaData;
  if(lreq == NULL) {
    printk(KERN_ERR "%s:Error allocating request\n", __FUNCTION__);
    return CPA_STATUS_FAIL;
  }

  lreq->symop = pOpData;
  lreq->src_bufflist = pSrcBuffer;
  lreq->dest_bufflist = pDstBuffer;
  lreq->callback_tag = pCallbackTag;

  /* Invoke the front end driver 
   * Assuming single buffer for now */
  
  app_req.key_size = (uint16_t)s_ctx->cipher_data->cipherKeyLenInBytes;
  app_req.key = s_ctx->cipher_data->pCipherKey;

  app_req.iv_size = pOpData->ivLenInBytes;
  app_req.iv = pOpData->pIv;
   
  app_req.msg_size = pSrcBuffer->pBuffers->dataLenInBytes;
  app_req.msg = pSrcBuffer->pBuffers->pData;
  app_req.presp = pDstBuffer->pBuffers->pData;

  app_req.callbk_tag = lreq;

  if(glob_info.fn_queue_request == NULL) {
    printk(KERN_ERR "fn_queue_request NULL\n");
    return CPA_STATUS_FAIL;
  }

  if(!glob_info.fn_queue_request(&app_req, glob_info.drv_meta)) {
     return CPA_STATUS_SUCCESS;
  } else {
     printk(KERN_ERR "%s: ixp_queue_request failed\n", __FUNCTION__);
     return CPA_STATUS_FAIL;
  }
}

EXPORT_SYMBOL(cpaCySymPerformOp);

void
crypto_wrapper_cb(void *callbk,
	          struct app_response *resp) {

  local_req_t *lreq = (local_req_t *) callbk;
  struct sess_ctx *s_ctx = lreq->symop->pSessionCtx;
  CpaStatus status = CPA_STATUS_FAIL;

  if(resp) {
    if(resp->status == IXP_RSP_OKAY)
	status = CPA_STATUS_SUCCESS;
  }  

  s_ctx->pSymCb(lreq->callback_tag, 
		status,
		CPA_CY_SYM_OP_CIPHER,
		lreq->symop,
		lreq->dest_bufflist,
		false);

  return;
}

void init_wrapper_lib(void *meta, libcb_t *cb, frontend_queue_t ixp_queue) {

  glob_info.drv_meta = meta;
  glob_info.fn_queue_request = ixp_queue;
  *cb = (libcb_t)crypto_wrapper_cb;

  glob_info.is_ready = 1;

  return; 
}

EXPORT_SYMBOL(init_wrapper_lib);

static int wrapper_init(void) {
  printk("Wrapper Lib Loading\n");

  glob_info.drv_meta = NULL;
  glob_info.fn_queue_request = NULL;
  glob_info.is_ready = 0;

  return 0;
}

static void wrapper_cleanup(void) {
  printk("Wrapper module exiting\n");
  return;
}

module_init(wrapper_init);
module_exit(wrapper_cleanup);

MODULE_AUTHOR("Venkat");
MODULE_DESCRIPTION("Tolapai DomU Wrapper");
MODULE_LICENSE("Dual BSD/GPL");


