/******************************************************************************
 * ixp.h
 *
 * Tolapai interface for Xen guest OSes.
 *
 * Copyright (c), Venkat
 */

#ifndef __XEN_IXP_H__
#define __XEN_IXP_H__

#include "ring.h"
#include "../grant_table.h"

/*
 * Front->back notifications: When enqueuing a new request, sending a
 * notification can be made conditional on req_event (i.e., the generic
 * hold-off mechanism provided by the ring macros). Backends must set
 * req_event appropriately (e.g., using RING_FINAL_CHECK_FOR_REQUESTS()).
 *
 * Back->front notifications: When enqueuing a new response, sending a
 * notification can be made conditional on rsp_event (i.e., the generic
 * hold-off mechanism provided by the ring macros). Frontends must set
 * rsp_event appropriately (e.g., using RING_FINAL_CHECK_FOR_RESPONSES()).
 */

typedef uint16_t ixp_vdev_t;

/*
 * REQUEST CODES.
 */
#define IXP_OP_3DES_ENCRYPT              0
#define IXP_OP_3DES_DECRYPT              1

/*
 * Maximum scatter/gather segments per request.
 * This is carefully chosen so that sizeof(struct blkif_ring) <= PAGE_SIZE.
 * NB. This could be 12 if the ring indexes weren't stored in the same page.
 */
#define IXP_MAX_SEGMENTS_PER_REQUEST 2

struct ixp_request {
	uint8_t        operation;    /* BLKIF_OP_???                         */
	uint8_t        nr_segments;  /* number of segments                   */
	ixp_vdev_t     handle;       /* only for read/write requests         */
	uint64_t       id;           /* private guest value, echoed in resp  */
  
	struct ixp_request_segment {
		grant_ref_t gref;        /* reference to I/O buffer frame        */
	} seg[IXP_MAX_SEGMENTS_PER_REQUEST];
};

struct ixp_response {
	uint64_t        id;              /* copied from request */
	uint8_t         operation;       /* copied from request */
	int16_t         status;          /* BLKIF_RSP_???       */
	uint16_t	resp_size;
};


struct des_request {
  uint16_t key_size;
  uint16_t iv_size;
  uint16_t msg_size;
};

struct cb_params {
  char *presp;
  void *callbk_tag;
};

typedef struct cb_params cb_params_t;


/*
 * STATUS RETURN CODES.
 */
 /* Operation not supported (only happens on barrier writes). */
#define IXP_RSP_EOPNOTSUPP  -2
 /* Operation failed for some unspecified reason (-EIO). */
#define IXP_RSP_ERROR       -1
 /* Operation completed successfully. */
#define IXP_RSP_OKAY         0

/*
 * Generate ixp ring structures and types.
 */

DEFINE_RING_TYPES(ixp, struct ixp_request, struct ixp_response);

#endif 
