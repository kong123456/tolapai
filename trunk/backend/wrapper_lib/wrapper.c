/* 
 *
 Tolapai backend driver wrapper library 
 Author: venkat (venkatraghavan@gatech.edu
*
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <cpa_cy_sym.h>
#include <cpa_cy_im.h>
#include <cpa_sample_utils.h>


#include <ixp_common.h>
#include <backend/wrapper.h>

#define TIMEOUT_MS 5000 /* 5 seconds*/

int debugParam = 1;

struct sess_ctx {
	CpaCySymOpData *symop;
	CpaCySymCipherSetupData *cipher_data;
	CpaBufferList *src_bufflist;
	CpaBufferList *dest_bufflist;
	CpaCySymCbFunc pSymCb;
	void *callback_tag;
};

struct wrap_lib {
	void *drv_meta;
	libcb_t drv_cb;
	int is_ready;
} glob_info;

struct des_req {
  des_hdr_t *hdr;
  char *key;
  char *iv;
  char *msg;
  char *resp;
  void *cb;
};

typedef struct des_req des_req_t;



void dump_message(char *msg,unsigned int size) {
  int i = 0, j = 0;

  printk(KERN_ERR "dump: size -- %d\n", size);
  
  i = size / 4;

  for(j = 0; j < i; j++) {
    printk(KERN_ERR "0x%04x: 0x%08X\n", j*4, *(unsigned int *)&msg[j * 4]);
  }  
  
}


/******************************************************************************
 * sampleCipherFunctional
 ****************************************************************************/

/**
 *****************************************************************************
 *  sampleCipherFunctional
 * Symmetric callback function
 * It is a signal that the operation is completed. The user can call the
 * application above, free the memory, etc.
 * In this example, the function only sets the complete variable to indicate
 * it has been called
 *
 ****************************************************************************/
static void
symCallback(void *pCallbackTag,
        CpaStatus status,
        const CpaCySymOp operationType,
        void *pOpData,
        CpaBufferList *pDstBuffer,
        CpaBoolean verifyResult)
{

    struct app_response aresp;
    CpaCySymOpData  *op_data = NULL;

    if (NULL != pCallbackTag)
    {
         	
 	op_data = (CpaCySymOpData *) pOpData;
	
  	aresp.status = status;
	aresp.presp = pDstBuffer->pBuffers->pData;

 	glob_info.drv_cb(glob_info.drv_meta, pCallbackTag, &aresp);
	
	cpaCySymRemoveSession(CPA_INSTANCE_HANDLE_SINGLE, op_data->pSessionCtx);

	OS_FREE(op_data->pSessionCtx);
	OS_FREE(pDstBuffer->pPrivateMetaData);
    	OS_FREE(pDstBuffer->pBuffers->pData);
	OS_FREE(pDstBuffer);
    	OS_FREE(op_data);
    }
}

/**
 *****************************************************************************
 *  sampleCipherFunctional
 * Perform an cipher operation
 *
 ****************************************************************************/
static CpaStatus
cipherPerformOp(des_req_t *local_req, CpaCySymSessionCtx pSessionCtx)
{
    CpaStatus       status          = CPA_STATUS_SUCCESS;
    Cpa8U           *pBufferMeta    = NULL;
    Cpa8U           *pSrcBuffer     = NULL;
    Cpa8U           *pIvBuffer      = NULL;
    Cpa32U          bufferMetaSize  = 0;
    CpaBufferList   *pBufferList    = NULL;
    CpaFlatBuffer   *pFlatBuffer    = NULL;
    CpaCySymOpData  *pOpData        = NULL;
    //Cpa32U          bufferSize      = sizeof(sampleCipherSrc);
    Cpa32U          bufferSize      = local_req->hdr->msg_size;
    Cpa32U          numBuffers      = 1;  /* only using 1 buffer in this case */
    Cpa32U      bufferListMemSize   = sizeof(CpaBufferList) +
                                        (numBuffers * sizeof(CpaFlatBuffer));

    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */

    status = cpaCyBufferListGetMetaSize(CPA_INSTANCE_HANDLE_SINGLE,
                				numBuffers, &bufferMetaSize);

    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferMeta, bufferMetaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pBufferList, bufferListMemSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pFlatBuffer,sizeof(CpaFlatBuffer));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&pSrcBuffer, bufferSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        pIvBuffer = local_req->iv;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(pSrcBuffer, local_req->msg, local_req->hdr->msg_size);

        pBufferList->pBuffers = pFlatBuffer;
        pBufferList->numBuffers = 1;
        pBufferList->pPrivateMetaData = pBufferMeta;

        pFlatBuffer->dataLenInBytes = bufferSize;
        pFlatBuffer->pData = pSrcBuffer;

        status = OS_MALLOC(&pOpData, sizeof(CpaCySymOpData));
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /** Populate the structure containing the operational data that is
         * needed to run the algorithm:
         * - packet type information (the algorithm can operate on a full
         * packet, perform a partial operation and maintain the state or
         * complete the last part of a multi-part operation)
         * - the initialization vector and its length
         * - the offset in the source buffer
         * - the length of the source message
         */
        pOpData->pSessionCtx = pSessionCtx;
        pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        pOpData->pIv = pIvBuffer;
        pOpData->ivLenInBytes = local_req->hdr->iv_size;
        pOpData->cryptoStartSrcOffsetInBytes = 0;
        pOpData->messageLenToCipherInBytes = local_req->hdr->msg_size;

    }

    if (CPA_STATUS_SUCCESS == status)
    {

        /** Perform symmetric operation */
        status = cpaCySymPerformOp(CPA_INSTANCE_HANDLE_SINGLE,
                (void *)local_req->cb, /* data sent as is to the callback function*/
                pOpData,           /* operational data struct */
                pBufferList,       /* source buffer list */
                pBufferList,       /* same src & dst for an in-place operation*/
                NULL);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymPerformOp failed. (status = %d)\n", status);
        }
    }

    return status;
}

CpaStatus
cipherSample(des_req_t *local_req)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;
    CpaCySymSessionSetupData sessionSetupData = {0};
    CpaCySymStats symStats = {0};

    //status = cpaCyStartInstance(CPA_INSTANCE_HANDLE_SINGLE);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Populate the session setup structure for the operation required */
        sessionSetupData.sessionPriority =  CPA_CY_PRIORITY_NORMAL;
        sessionSetupData.symOperation =     CPA_CY_SYM_OP_CIPHER;
        sessionSetupData.cipherSetupData.cipherAlgorithm =
                                            CPA_CY_SYM_CIPHER_3DES_CBC;
        sessionSetupData.cipherSetupData.pCipherKey = local_req->key;
        sessionSetupData.cipherSetupData.cipherKeyLenInBytes = local_req->hdr->key_size;
        sessionSetupData.cipherSetupData.cipherDirection =
                                            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

        /* Determine size of session context to allocate */
        status = cpaCySymSessionCtxGetSize(CPA_INSTANCE_HANDLE_SINGLE,
                    &sessionSetupData, &sessionCtxSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate session context */
        status = OS_MALLOC(&pSessionCtx, sessionCtxSize);
    }


    /** Initialize the Cipher session */
    if (CPA_STATUS_SUCCESS == status) {
        status = cpaCySymInitSession(CPA_INSTANCE_HANDLE_SINGLE,
                            symCallback,        /* callback function */
                            &sessionSetupData,  /* session setup data */
                            pSessionCtx);       /* output of the function*/
    }

    if (CPA_STATUS_SUCCESS == status)
    {

        /* Perform Cipher operation */
        status = cipherPerformOp(local_req, pSessionCtx);

        /* Remove the session - session init has already succeeded 
        PRINT_DBG("cpaCySymRemoveSession\n");
        sessionStatus = cpaCySymRemoveSession(
                            CPA_INSTANCE_HANDLE_SINGLE, pSessionCtx);

        * maintain status of remove session only when status of all operations
         * before it are successful. *
        if (CPA_STATUS_SUCCESS == status)
        {
            status = sessionStatus;
        }*/
    }

    /*if (CPA_STATUS_SUCCESS == status)
    {
        * Query symmetric statistics *
        * NOTE: Stats can also be examined by the file /proc/icp-crypto/sym
         * in the proc filesystem *
        status = cpaCySymQueryStats(CPA_INSTANCE_HANDLE_SINGLE, &symStats);

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCySymQueryStats failed, status = %d\n", status);
        }
        else
        {
            PRINT_DBG("Number of symmetric operation completed: %d\n",
                        symStats.numSymOpCompleted);
        }
    }*/

    /* Clean up */

    //cpaCyStopInstance(CPA_INSTANCE_HANDLE_SINGLE);

    if (CPA_STATUS_SUCCESS == status)
    {
        //PRINT_DBG("Sample code ran successfully\n");
    }
    else
    {
        PRINT_DBG("Sample code failed with status of %d\n", status);
    }

    return status;
}


int ixp_wrapper_service_request(app_request_t *areq) {
  des_hdr_t *req_hdr = NULL;
  des_req_t local_req;  
  unsigned int offset = 0;

  switch(areq->op) {
    case IXP_OP_3DES_ENCRYPT:
     req_hdr = (des_hdr_t *) areq->req_buf;
     local_req.hdr = req_hdr;

     offset += sizeof(des_hdr_t);
     local_req.key = (char *) req_hdr + offset;

     offset += req_hdr->key_size;
     local_req.iv = (char *) req_hdr + offset;

     offset += req_hdr->iv_size;
     local_req.msg = (char *) req_hdr + offset;

     local_req.cb = areq->callbk_tag;
     return (cipherSample(&local_req));
     break;

    default:
     return 1;
  }
}

EXPORT_SYMBOL(ixp_wrapper_service_request);

void init_wrapper_lib(void *meta, libcb_t cb) {
	printk(KERN_ERR "%s\n", __FUNCTION__);

	glob_info.drv_meta = meta;
	glob_info.drv_cb = cb;

	glob_info.is_ready = 1;

	return;
}
EXPORT_SYMBOL(init_wrapper_lib);

static int wrapper_init(void) {
	CpaStatus status = CPA_STATUS_FAIL;

	printk(KERN_ERR "%s\n", __FUNCTION__);

	glob_info.drv_meta = NULL;
	glob_info.drv_cb = NULL;
	glob_info.is_ready = 0;

        PRINT_DBG("cpaCyStartInstance\n");
        status = cpaCyStartInstance(CPA_INSTANCE_HANDLE_SINGLE);

  	if(status != CPA_STATUS_SUCCESS) {
	  printk(KERN_ERR "Unable to start instance\n");
	}

	return 0;
}

static void wrapper_cleanup(void) {
	printk(KERN_ERR "%s\n", __FUNCTION__);

	PRINT_DBG("cpaCyStopInstance\n");
    	cpaCyStopInstance(CPA_INSTANCE_HANDLE_SINGLE);
	
	return;
}

module_init(wrapper_init);
module_exit(wrapper_cleanup);

MODULE_AUTHOR("venkat");
MODULE_DESCRIPTION("Tolapai Dom0 Wrapper");
MODULE_LICENSE("Dual BSD/GPL");


