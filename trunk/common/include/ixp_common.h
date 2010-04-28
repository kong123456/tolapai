/******************************************************************************
 * ixp.h
 *
 * Tolapai interface for Xen guest OSes.
 *
 * Author: Venkat
 */


#ifndef __IXP_COMMON_H__
#define __IXP_COMMON_H__

#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/pgalloc.h>
#include <asm/hypervisor.h>
#include <xen/blkif.h>
#include <xen/grant_table.h>
#include <xen/xenbus.h>

#include <xen/interface/io/ring.h>
#include <xen/interface/grant_table.h>

#define DPRINTK(_f, _a...)			\
	pr_debug("(file=%s, line=%d) " _f,	\
		 __FILE__ , __LINE__ , ## _a )

/*
 * Maximum scatter/gather segments per request.
 * This is carefully chosen so that sizeof(struct ixp_ring) <= PAGE_SIZE.
 **/


#define IXPIF_MAX_SEGMENTS_PER_REQUEST 2

typedef uint16_t ixp_vdev_t;

/*
 * REQUEST CODES.
 */
#define IXP_OP_3DES_ENCRYPT              0
#define IXP_OP_3DES_DECRYPT              1
/*
 * STATUS RETURN CODES.
 */
 /* Operation not supported (only happens on barrier writes). */
#define IXPIF_RSP_EOPNOTSUPP  -2
 /* Operation failed for some unspecified reason (-EIO). */
#define IXPIF_RSP_ERROR       -1
 /* Operation completed successfully. */
#define IXPIF_RSP_OKAY         0

struct ixp_request {
	uint8_t        operation;    /* BLKIF_OP_???                         */
	uint8_t        nr_segments;  /* number of segments                   */
	ixp_vdev_t     handle;       /* only for read/write requests         */
	uint64_t       id;           /* private guest value, echoed in resp  */

	struct ixp_request_segment {
		grant_ref_t gref;        /* reference to I/O buffer frame        */
	} seg[IXPIF_MAX_SEGMENTS_PER_REQUEST];
};

struct ixp_response {
	uint64_t        id;              /* copied from request */
	uint8_t         operation;       /* copied from request */
	int16_t         status;          /* BLKIF_RSP_???       */
	uint16_t 	resp_size;
};


struct des_request {
  uint16_t key_size;
  uint16_t iv_size;
  uint16_t msg_size;
};

typedef struct des_request des_request_t;
typedef struct des_request des_hdr_t;

struct cb_params {
  char *presp;
  void *callbk_tag;
};

typedef struct cb_params cb_params_t;

DEFINE_RING_TYPES(ixp, struct ixp_request, struct ixp_response);

#endif /* __BLKIF__BACKEND__COMMON_H__ */
