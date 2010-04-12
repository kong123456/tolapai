/******************************************************************************
 * arch/xen/drivers/blkif/backend/main.c
 *
 * Back-end of the driver for virtual block devices. This portion of the
 * driver exports a 'unified' block-device interface that can be accessed
 * by any operating system that implements a compatible front end. A
 * reference front-end implementation can be found in:
 *  arch/xen/drivers/blkif/frontend
 *
 * Copyright (c) 2003-2004, Keir Fraser & Steve Hand
 * Copyright (c) 2005, Christopher Clark
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/freezer.h>

#include <xen/balloon.h>
#include <xen/events.h>
#include <xen/page.h>
#include <asm/xen/hypervisor.h>
#include <asm/xen/hypercall.h>
#include <xen/interface/io/ixp_back_common.h>

#include <stdarg.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include "ixpback.h"

#include <xen/events.h>
#include <xen/grant_table.h>
#include <linux/kthread.h>


static char expectedOutput[] = {
        0x35,0x0C,0x46,0xF8,0xFE,0x13,0x8A,0x7C,0x9B,0x66,0x83,0x5F,
        0x94,0xDC,0x4F,0x96,0x66,0x56,0x35,0xC3,0xFA,0xFD,0x51,0xA1,
        0xC9,0x3B,0xAF,0x06,0x2A,0xA9,0x54,0x0D,0xF1,0x0B,0xBB,0xB1,
        0x27,0x15,0x9D,0xD2,0x08,0xAC,0xF0,0x92,0x47,0x19,0xE2,0xC1,
        0x47,0xAC,0x34,0x30,0x8C,0x95,0x1B,0x14,0xD4,0x71,0x37,0x4B,
        0x50,0xCB,0x73,0xAA,0x4F,0x98,0x36,0xF1,0x97,0xE2,0x8C,0x37,
        0x6C,0x44,0xC2,0xFD,0xAD,0xE4,0xF5,0x56,0x62,0x92,0xEF,0x84,
        0x9E,0x33,0x0D,0x5B,0x34,0x27,0xA0,0x2B,0x9B,0x7C,0xE7,0x8A,
};



#define STATUS_SUCCESS 0

/*
 * These are rather arbitrary. They are fairly large because adjacent requests
 * pulled from a communication ring are quite likely to end up being part of
 * the same scatter/gather request at the disc.
 *
 * ** TRY INCREASING 'blkif_reqs' IF WRITE SPEEDS SEEM TOO LOW **
 *
 * This will increase the chances of being able to write whole tracks.
 * 64 should be enough to keep us competitive with Linux.
 */
static int blkif_reqs = 100;
/*
module_param_named(reqs, blkif_reqs, int, 0);
MODULE_PARM_DESC(reqs, "Number of blkback requests to allocate"); */

// Run-time switchable: /sys/module/blkback/parameters/
static unsigned int log_stats = 0;
static unsigned int debug_lvl = 1;
/*module_param(log_stats, int, 0644);
module_param(debug_lvl, int, 0644);*/

/*
 * Each outstanding request that we've passed to the lower device layers has a
 * 'pending_req' allocated to it. Each buffer_head that completes decrements
 * the pendcnt towards zero. When it hits zero, the specified domain has a
 * response queued for it, with the saved 'id' passed back.
 */
typedef struct {
	ixpif_t       *ixpif;
	u64            id;
	int            nr_pages;
	atomic_t       pendcnt;
	unsigned short operation;
	int            status;
	struct list_head free_list;
} pending_req_t;

static pending_req_t *pending_reqs;
static struct list_head pending_free;
static DEFINE_SPINLOCK(pending_free_lock);
static DECLARE_WAIT_QUEUE_HEAD(pending_free_wq);

#define BLKBACK_INVALID_HANDLE (~0)

static struct page **pending_pages;
static grant_handle_t *pending_grant_handles;

static inline int vaddr_pagenr(pending_req_t *req, int seg)
{
	return (req - pending_reqs) * IXPIF_MAX_SEGMENTS_PER_REQUEST + seg;
}

#define pending_page(req, seg) pending_pages[vaddr_pagenr(req, seg)]

static inline unsigned long vaddr(pending_req_t *req, int seg)
{
	unsigned long pfn = page_to_pfn(pending_page(req, seg));
	return (unsigned long)pfn_to_kaddr(pfn);
}

#define pending_handle(_req, _seg) \
	(pending_grant_handles[vaddr_pagenr(_req, _seg)])


static int do_crypto_io_op(ixpif_t *blkif);
//static void dispatch_rw_block_io(blkif_t *blkif,
//				 struct blkif_request *req,
//				 pending_req_t *pending_req);
static void make_response(ixpif_t *blkif, u64 id,
			  unsigned short op, int st, int resp_size);


extern int ixp_wrapper_service_request(app_request_t *);
extern void init_wrapper_lib(void *b, libcb_t cb);

///******************************************************************
// * misc small helpers
// */
static pending_req_t* alloc_req(void)
{
	pending_req_t *req = NULL;
	unsigned long flags;

	spin_lock_irqsave(&pending_free_lock, flags);
	if (!list_empty(&pending_free)) {
		req = list_entry(pending_free.next, pending_req_t, free_list);
		list_del(&req->free_list);
	}
	spin_unlock_irqrestore(&pending_free_lock, flags);
	return req;
}

static void free_req(pending_req_t *req)
{
	unsigned long flags;
	int was_empty;

	spin_lock_irqsave(&pending_free_lock, flags);
	was_empty = list_empty(&pending_free);
	list_add(&req->free_list, &pending_free);
	spin_unlock_irqrestore(&pending_free_lock, flags);
	if (was_empty)
		wake_up(&pending_free_wq);
}

//static void unplug_queue(blkif_t *blkif)
//{
//	if (blkif->plug == NULL)
//		return;
//	if (blkif->plug->unplug_fn)
//		blkif->plug->unplug_fn(blkif->plug);
//	blk_put_queue(blkif->plug);
//	blkif->plug = NULL;
//}
//
//static void plug_queue(blkif_t *blkif, struct block_device *bdev)
//{
//	struct request_queue *q = bdev_get_queue(bdev);
//
//	if (q == blkif->plug)
//		return;
//	unplug_queue(blkif);
//	blk_get_queue(q);
//	blkif->plug = q;
//}
//

void dump_message(char *msg,unsigned int size) {
  int i = 0, j = 0;

  printk(KERN_ERR "dump: size -- %d\n", size);
  
  i = size / 4;

  for(j = 0; j < i; j++) {
    printk(KERN_ERR "0x%04x: 0x%08X\n", j*4, *(unsigned int *)&msg[j * 4]);
  }  
  
}

static void fast_flush_area(pending_req_t *req)
{
	struct gnttab_unmap_grant_ref unmap[IXPIF_MAX_SEGMENTS_PER_REQUEST];
	unsigned int i, invcount = 0;
	grant_handle_t handle;
	int ret;

	for (i = 0; i < req->nr_pages; i++) {
		handle = pending_handle(req, i);
		if (handle == BLKBACK_INVALID_HANDLE)
			continue;
		ixpback_pagemap_clear(pending_page(req, i));
		gnttab_set_unmap_op(&unmap[invcount], vaddr(req, i),
				    GNTMAP_host_map, handle);
		pending_handle(req, i) = BLKBACK_INVALID_HANDLE;
		invcount++;
	}

	ret = HYPERVISOR_grant_table_op(
		GNTTABOP_unmap_grant_ref, unmap, invcount);
	BUG_ON(ret);
}


void ixpback_cb(void *meta, void *tag, app_response_t *aresp) {
  pending_req_t *pending_req = NULL;
  ixpif_t *ixpif = (ixpif_t *) meta;
  char *presp = NULL;

  pending_req = (pending_req_t *)  tag;

  if(pending_req != NULL) {
    if(aresp->status != STATUS_SUCCESS)
       pending_req->status = BLKIF_RSP_ERROR; 
    else
       pending_req->status = BLKIF_RSP_OKAY;

    presp = vaddr(pending_req, 0);

    if(presp != NULL && aresp->presp != NULL) {
	int off, msg_size;
	off = sizeof(struct des_request) + ((struct des_request *) presp)->key_size + ((struct des_request *) presp)->iv_size;
	msg_size = ((struct des_request *) presp)->msg_size;

	presp += off;
	memcpy(presp, aresp->presp, msg_size);
	//dump_message(presp, 96);
    }

    make_response(ixpif, pending_req->id, pending_req->operation, pending_req->status, 0);

    if (atomic_dec_and_test(&pending_req->pendcnt)) {
		fast_flush_area(pending_req);
		blkif_put(pending_req->ixpif);
		free_req(pending_req);
    }


  }

  return;

}


//
///******************************************************************
// * SCHEDULER FUNCTIONS
// */
//
//static void print_stats(blkif_t *blkif)
//{
//	printk(KERN_DEBUG "%s: oo %3d  |  rd %4d  |  wr %4d  |  br %4d\n",
//	       current->comm, blkif->st_oo_req,
//	       blkif->st_rd_req, blkif->st_wr_req, blkif->st_br_req);
//	blkif->st_print = jiffies + msecs_to_jiffies(10 * 1000);
//	blkif->st_rd_req = 0;
//	blkif->st_wr_req = 0;
//	blkif->st_oo_req = 0;
//}

static void dispatch_crypto_io(ixpif_t *ixpif,
			       struct ixp_request *req,
			       pending_req_t *pending_req)
{
	struct gnttab_map_grant_ref map[IXPIF_MAX_SEGMENTS_PER_REQUEST];
	struct phys_req preq;
	struct des_request *dreq;
	struct {
		char *buf; 
	} seg[IXPIF_MAX_SEGMENTS_PER_REQUEST];
	struct vm_struct *domu_page;
	unsigned int nseg;
	int ret, i;
	int operation;
	app_request_t wr_req;
	char *rsp_ptr = NULL, *curr_pos = NULL;

	switch (req->operation) {
	case IXP_OP_3DES_ENCRYPT:
		operation = IXP_OP_3DES_ENCRYPT;
		break;
	default:
		operation = 0; /* make gcc happy */
		BUG();
	}

	/* Check that number of segments is sane. */
	nseg = req->nr_segments;
	if (nseg > IXPIF_MAX_SEGMENTS_PER_REQUEST) {
		printk("nseg > max_segments\n");
		DPRINTK("Bad number of segments in request (%d)\n", nseg);
		goto fail_response;
	}

	pending_req->ixpif     = ixpif;
	pending_req->id        = req->id;
	pending_req->operation = req->operation;
	pending_req->status    = BLKIF_RSP_OKAY;
	pending_req->nr_pages  = nseg;

	//printk(KERN_ERR "About to host_map request page, nseg: %d gref: %d\n", nseg, req->seg[0].gref);
	//printk(KERN_ERR "ixpif->domid: %d\n", ixpif->domid);

	/*if((domu_page = alloc_vm_area(PAGE_SIZE)) == NULL) {
	  printk(KERN_ERR "alloc_vm_area failure\n");
	  goto fail_response;
	}*/

	for (i = 0; i < nseg; i++) {
		uint32_t flags;

		flags = GNTMAP_host_map;
		gnttab_set_map_op(&map[i], vaddr(pending_req, i), flags,
				  req->seg[i].gref, ixpif->domid);
	}

	//printk(KERN_ERR "HYPERVISOR call map request grant ref: host_addr: %p dom: %d ref: %d\n",
				//map[0].host_addr, map[0].dom, map[0].ref);

	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, map, nseg);
	BUG_ON(ret);
	
	//printk(KERN_ERR "grant_table_op: status: %d\n", map[0].status);
	
	for (i = 0; i < nseg; i++) {
		if (unlikely(map[i].status != 0)) {
			printk(KERN_ERR "Invalid buffer -- could not remap it\n");
			DPRINTK("invalid buffer -- could not remap it\n");
			map[i].handle = BLKBACK_INVALID_HANDLE;
			ret |= 1;
			continue;
		}

		seg[i].buf = (char *)vaddr(pending_req, i);
		
		dreq = (struct des_request *)seg[i].buf;
		//printk(KERN_ERR "Request retrieved: iv_size: %d key_size: %d msg_size: %d",
		//		  dreq->iv_size, dreq->key_size, dreq->msg_size);

		ixpback_pagemap_set(vaddr_pagenr(pending_req, i),
				    pending_page(pending_req, i),
				    ixpif->domid, req->handle,
				    req->seg[i].gref);
		pending_handle(pending_req, i) = map[i].handle;
	}


	wr_req.op = pending_req->operation;
	wr_req.req_buf = (char *)seg[0].buf;
	wr_req.callbk_tag = (void *) pending_req;

	//curr_pos = seg[0].buf + sizeof(struct des_request);
	//dump_message(curr_pos, dreq->key_size);

	//curr_pos +=  dreq->key_size;
	//dump_message(curr_pos, dreq->iv_size);

	//curr_pos +=  dreq->iv_size;
	//dump_message(curr_pos, dreq->msg_size);

	if((ixp_wrapper_service_request(&wr_req)) != STATUS_SUCCESS) {
	   goto fail_response;
	}
		
	//printk(KERN_ERR "Request processed\n");

	if (ret)
		goto fail_flush;

//	plug_queue(blkif, preq.bdev);
	atomic_set(&pending_req->pendcnt, 1);
	blkif_get(ixpif);

	return;

 fail_flush:
	//printk(KERN_ERR "fast_flush:\n");
	fast_flush_area(pending_req);
 fail_response:
	printk(KERN_ERR "fail_response\n");
//	make_response(blkif, req->id, req->operation, BLKIF_RSP_ERROR);
	free_req(pending_req);
	msleep(1); /* back off a bit */
	return;

}

static int do_crypto_io_op(ixpif_t *ixpif)
{
	struct ixp_back_ring *ixp_ring; 
	struct ixp_request req;
	pending_req_t *pending_req;
	RING_IDX rc, rp;
	int more_to_do = 0;

	ixp_ring = &ixpif->ixp_ring;
	rc = ixp_ring->req_cons;
	rp = ixp_ring->sring->req_prod;
	rmb(); /* Ensure we see queued requests up to 'rp'. */

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);

	while (rc != rp) {

		if (RING_REQUEST_CONS_OVERFLOW(ixp_ring, rc))
			break;

		if (kthread_should_stop()) {
			more_to_do = 1;
			break;
		}

		pending_req = alloc_req();
		if (NULL == pending_req) {
			ixpif->st_oo_req++;
			more_to_do = 1;
			break;
		}
		
		memcpy(&req, RING_GET_REQUEST(ixp_ring, rc), sizeof(req));
	
		ixp_ring->req_cons = ++rc; /* before make_response() */

		/* Apply all sanity checks to /private copy/ of request. */
		barrier();

		//printk(KERN_ERR "operation=%d,  \n", req.operation);


		switch (req.operation) {
		case IXP_OP_3DES_ENCRYPT:
			dispatch_crypto_io(ixpif, &req, pending_req);
			break;
		default:
			/* A good sign something is wrong: sleep for a while to
			 * avoid excessive CPU consumption by a bad guest. */
			msleep(1);
			DPRINTK("error: unknown crypto operation [%d]\n",
				req.operation);
//			make_response(blkif, req.id, req.operation,
//				      BLKIF_RSP_ERROR);
			free_req(pending_req);
			break;
		}

		/* Yield point for this unbounded loop. */
		cond_resched();
	}

	return more_to_do;
}

int ixpif_schedule(void *arg)
{
	ixpif_t *ixpif;

	ixpif = (ixpif_t *)arg;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);

	blkif_get(ixpif);

	if (debug_lvl)
		printk(KERN_DEBUG "%s: started\n", current->comm);

	init_wrapper_lib(ixpif, ixpback_cb);

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_interruptible(ixpif->wq,	
					  ixpif->waiting_reqs || kthread_should_stop());
		wait_event_interruptible(pending_free_wq,
					 !list_empty(&pending_free) || kthread_should_stop());

		ixpif->waiting_reqs = 0;
		smp_mb(); /* clear flag *before* checking for work */

		if (do_crypto_io_op(ixpif))
			ixpif->waiting_reqs = 1;
		
		//unplug_queue(blkif);

		/*if (log_stats && time_after(jiffies, blkif->st_print))
			print_stats(blkif);*/
	}

	/*if (log_stats)
		print_stats(blkif);*/
	if (debug_lvl)
		printk(KERN_DEBUG "%s: exiting\n", current->comm);

	ixpif->xenblkd = NULL;
	blkif_put(ixpif);

	return 0;
}
//
///******************************************************************
// * COMPLETION CALLBACK -- Called as bh->b_end_io()
// */
//
//static void __end_block_io_op(pending_req_t *pending_req, int error)
//{
//	/* An error fails the entire request. */
//	if ((pending_req->operation == BLKIF_OP_WRITE_BARRIER) &&
//	    (error == -EOPNOTSUPP)) {
//		DPRINTK("blkback: write barrier op failed, not supported\n");
//		blkback_barrier(XBT_NIL, pending_req->blkif->be, 0);
//		pending_req->status = BLKIF_RSP_EOPNOTSUPP;
//	} else if (error) {
//		DPRINTK("Buffer not up-to-date at end of operation, "
//			"error=%d\n", error);
//		pending_req->status = BLKIF_RSP_ERROR;
//	}
//
//	if (atomic_dec_and_test(&pending_req->pendcnt)) {
//		fast_flush_area(pending_req);
//		make_response(pending_req->blkif, pending_req->id,
//			      pending_req->operation, pending_req->status);
//		blkif_put(pending_req->blkif);
//		free_req(pending_req);
//	}
//}
//
//static void end_block_io_op(struct bio *bio, int error)
//{
//	__end_block_io_op(bio->bi_private, error);
//	bio_put(bio);
//}
/*
 *
 *
 *
 * 
 *
 *
 */

static struct kmem_cache *ixpif_cachep;

ixpif_t *ixpif_alloc(domid_t domid)
{
	ixpif_t *ixpif;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);

	ixpif = kmem_cache_alloc(ixpif_cachep, GFP_KERNEL);
	if (!ixpif)
		return ERR_PTR(-ENOMEM);

	memset(ixpif, 0, sizeof(*ixpif));
	ixpif->domid = domid;
	spin_lock_init(&ixpif->ixp_ring_lock);
	atomic_set(&ixpif->refcnt, 1);
	init_waitqueue_head(&ixpif->wq);
	//ixpif->st_print = jiffies;
	init_waitqueue_head(&ixpif->waiting_to_free);

	return ixpif;
}

static int map_frontend_page(ixpif_t *ixpif, unsigned long shared_page)
{
	struct gnttab_map_grant_ref op;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);

	gnttab_set_map_op(&op, (unsigned long)ixpif->ixp_ring_area->addr, GNTMAP_host_map, shared_page, ixpif->domid);

	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1))
		BUG();

	if (op.status) {
		DPRINTK(" Grant table operation failure !\n");
		return op.status;
	}

	ixpif->shmem_ref = shared_page;
	ixpif->shmem_handle = op.handle;

	return 0;
}

static void unmap_frontend_page(ixpif_t *ixpif)
{
	struct gnttab_unmap_grant_ref op;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);

	gnttab_set_unmap_op(&op, (unsigned long)ixpif->ixp_ring_area->addr,
			    GNTMAP_host_map, ixpif->shmem_handle);

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1))
		BUG();
}

int ixpif_map(ixpif_t *ixpif, unsigned long shared_page, unsigned int evtchn)
{
	int err;
	struct ixp_sring *sring;
	
	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);

	/* Already connected through? */
	if (ixpif->irq)
		return 0;

	if ( (ixpif->ixp_ring_area = alloc_vm_area(PAGE_SIZE)) == NULL )
		return -ENOMEM;

	err = map_frontend_page(ixpif, shared_page);
	if (err) {
		free_vm_area(ixpif->ixp_ring_area);
		return err;
	}

	sring = (struct ixp_sring *) ixpif->ixp_ring_area->addr;
	BACK_RING_INIT(&ixpif->ixp_ring, sring, PAGE_SIZE);

	err = bind_interdomain_evtchn_to_irqhandler(ixpif->domid, evtchn, ixpif_be_int, 0, "ixpif-backend", ixpif);
	if (err < 0)
	{
		unmap_frontend_page(ixpif);
		free_vm_area(ixpif->ixp_ring_area);
		ixpif->ixp_ring.sring = NULL;
		return err;
	}

	ixpif->irq = err;

	return 0;
}

void ixpif_disconnect(ixpif_t *ixpif)
{
	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	if (ixpif->xenblkd) {
		kthread_stop(ixpif->xenblkd);
		ixpif->xenblkd = NULL;
	}

	atomic_dec(&ixpif->refcnt);
	wait_event(ixpif->waiting_to_free, atomic_read(&ixpif->refcnt) == 0);
	atomic_inc(&ixpif->refcnt);

	if (ixpif->irq) {
		unbind_from_irqhandler(ixpif->irq, ixpif);
		ixpif->irq = 0;
	}

	if (ixpif->ixp_ring.sring) {
		unmap_frontend_page(ixpif);
		free_vm_area(ixpif->ixp_ring_area);
		ixpif->ixp_ring.sring = NULL;
	}
}

void ixpif_free(ixpif_t *ixpif)
{
	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	if (!atomic_dec_and_test(&ixpif->refcnt))
		BUG();
	kmem_cache_free(ixpif_cachep, ixpif);
}

int __init ixpif_interface_init(void)
{
	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	ixpif_cachep = kmem_cache_create("ixpif_cache", sizeof(ixpif_t),
					 0, 0, NULL);
	if (!ixpif_cachep)
		return -ENOMEM;

	return 0;
}


/*
 * 
 * ++
 */
#undef DPRINTK
#define DPRINTK(fmt, args...)				\
	pr_debug("blkback/xenbus (%s:%d) " fmt ".\n",	\
		 __FUNCTION__, __LINE__, ##args)

struct backend_info
{
	struct xenbus_device *dev;
	ixpif_t *ixpif;
	struct xenbus_watch backend_watch;
	unsigned created; //vkhurana
};

static void connect(struct backend_info *);
static int connect_ring(struct backend_info *);
static void backend_changed(struct xenbus_watch *, const char **,
			    unsigned int);

static int ixpback_name(ixpif_t *ixpif, char *buf)
{	
	char *devpath, *devname;
	struct xenbus_device *dev = ixpif->be->dev;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	/*devpath = xenbus_read(XBT_NIL, dev->nodename, "dev", NULL);
	if (IS_ERR(devpath))
		return PTR_ERR(devpath);*/

	/*if ((devname = strstr(devpath, "/dev/")) != NULL)
		devname += strlen("/dev/");
	else
		devname  = devpath;*/

	snprintf(buf, TASK_COMM_LEN, "ixpback.%d.%s", ixpif->domid, "tolapai");
	kfree(devpath);

	return 0;
}

static void update_ixpif_status(ixpif_t *ixpif)
{	
	int err;
	char name[TASK_COMM_LEN];

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);

	/* Not ready to connect? */
	if (!ixpif->irq)
		return;

	/* Already connected? */
	if (ixpif->be->dev->state == XenbusStateConnected)
		return;

	/* Attempt to connect: exit if we fail to. */
	connect(ixpif->be);
	if (ixpif->be->dev->state != XenbusStateConnected)
		return;

	err = ixpback_name(ixpif, name);
	if (err) {
		xenbus_dev_error(ixpif->be->dev, err, "get blkback dev name");
		return;
	}

	//printk(KERN_ERR "scheduling job!!! waiting_reqs=%d\n", ixpif->waiting_reqs);
	ixpif->xenblkd = kthread_run(ixpif_schedule, ixpif, name); //SCHEDULE!!!!!!!!!!!!

	if (IS_ERR(ixpif->xenblkd)) {
		err = PTR_ERR(ixpif->xenblkd);
		ixpif->xenblkd = NULL;
		xenbus_dev_error(ixpif->be->dev, err, "start xenblkd");
	}
}

static int ixpback_remove(struct xenbus_device *dev)
{	
	struct backend_info *be = dev->dev.driver_data;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	DPRINTK("");

	//printk("remove IF\n");

	if (be->backend_watch.node) {
		unregister_xenbus_watch(&be->backend_watch);
		kfree(be->backend_watch.node);
		be->backend_watch.node = NULL;
	}

	if (be->ixpif) {
		ixpif_disconnect(be->ixpif);
		ixpif_free(be->ixpif);
		be->ixpif = NULL;
	}

	kfree(be);
	dev->dev.driver_data = NULL;
	return 0;
}


/**
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures, and watch the store waiting for the hotplug scripts to tell us
 * the device's physical major and minor numbers.  Switch to InitWait.
 */
static int ixpback_probe(struct xenbus_device *dev,
			 const struct xenbus_device_id *id)
{	
	int err;
	struct backend_info *be = kzalloc(sizeof(struct backend_info), GFP_KERNEL);

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	if (!be) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating backend structure");
		return -ENOMEM;
	}
	be->dev = dev;
	dev->dev.driver_data = be;

	be->ixpif = ixpif_alloc(dev->otherend_id);
	if (IS_ERR(be->ixpif)) {
		err = PTR_ERR(be->ixpif);
		be->ixpif = NULL;
		xenbus_dev_fatal(dev, err, "creating block interface");
		goto fail;
	}

	/* setup back pointer */
	be->ixpif->be = be;

	err = xenbus_watch_pathfmt(dev, &be->backend_watch, backend_changed, "%s/%s", dev->nodename, "physical-device");
	if (err)
		goto fail;

	err = xenbus_switch_state(dev, XenbusStateInitWait);
	if (err)
		goto fail;

	return 0;

fail:
	DPRINTK("failed");
	ixpback_remove(dev);
	return err;
}


/**
 * Callback received when the hotplug scripts have placed the physical-device
 * node.  Read it and the mode node, and create a vbd.  If the frontend is
 * ready, connect.
 */
static void backend_changed(struct xenbus_watch *watch,
			    const char **vec, unsigned int len)
{	
	struct backend_info *be = container_of(watch, struct backend_info, backend_watch);
	struct xenbus_device *dev = be->dev;
	
	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	DPRINTK("");


	if (be->created == 0) {
		/* Front end dir is a number, which is used as the handle. */

		//printk("creating device...\n");

		/* We're potentially connected now */
		update_ixpif_status(be->ixpif);
	}
	else {
		//printk("device created... changing??\n");
	}
}


/**
 * Callback received when the frontend's state changes.
 */
static void frontend_changed(struct xenbus_device *dev,
			     enum xenbus_state frontend_state)
{	
	struct backend_info *be = dev->dev.driver_data;
	int err;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	DPRINTK("%s", xenbus_strstate(frontend_state));

	switch (frontend_state) {
	case XenbusStateInitialising:
		if (dev->state == XenbusStateClosed) {
			printk(KERN_INFO "%s: %s: prepare for reconnect\n", __FUNCTION__, dev->nodename);
			xenbus_switch_state(dev, XenbusStateInitWait);
		}
		break;

	case XenbusStateInitialised:
	case XenbusStateConnected:
		/* Ensure we connect even when two watches fire in
		   close successsion and we miss the intermediate value
		   of frontend_state. */
		if (dev->state == XenbusStateConnected)
			break;

		err = connect_ring(be);
		if (err)
			break;
		update_ixpif_status(be->ixpif);
		break;

	case XenbusStateClosing:
		ixpif_disconnect(be->ixpif);
		xenbus_switch_state(dev, XenbusStateClosing);
		break;

	case XenbusStateClosed:
		xenbus_switch_state(dev, XenbusStateClosed);
		if (xenbus_dev_is_online(dev))
			break;
		/* fall through if not online */
	case XenbusStateUnknown:
		device_unregister(&dev->dev);
		break;

	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %d at frontend",
				 frontend_state);
		break;
	}
}


/* ** Connection ** */


/**
 * Write the physical details regarding the block device to the store, and
 * switch to Connected state.
 */
static void connect(struct backend_info *be)
{
	struct xenbus_transaction xbt;
	int err;
	struct xenbus_device *dev = be->dev;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);

	DPRINTK("%s", dev->otherend);

	/* Supply the information about the device the frontend needs */
again:

	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		return;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err == -EAGAIN)
		goto again;
	if (err)
		xenbus_dev_fatal(dev, err, "ending transaction");

	err = xenbus_switch_state(dev, XenbusStateConnected);
	if (err)
		xenbus_dev_fatal(dev, err, "switching to Connected state",
				 dev->nodename);

	return;
 abort:
	xenbus_transaction_end(xbt, 1);
}


static int connect_ring(struct backend_info *be)
{	
	struct xenbus_device *dev = be->dev;
	unsigned long ring_ref;
	unsigned int evtchn;
	char protocol[64] = "";
	int err;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	DPRINTK("%s", dev->otherend);

	err = xenbus_gather(XBT_NIL, dev->otherend, "ring-ref", "%lu", &ring_ref, "event-channel", "%u", &evtchn, NULL);
	if (err) {
		xenbus_dev_fatal(dev, err,
				 "reading %s/ring-ref and event-channel",
				 dev->otherend);
		return err;
	}

	printk(KERN_INFO
	       "ixpback: ring-ref %ld, event-channel %d \n",
	       ring_ref, evtchn);
	
	// Map the shared frame, irq etc.
	err = ixpif_map(be->ixpif, ring_ref, evtchn);
	if (err) {
		xenbus_dev_fatal(dev, err, "mapping ring-ref %lu port %u",
				 ring_ref, evtchn);
		return err;
	}

	return 0;
}


/* ** Driver Registration ** */


static const struct xenbus_device_id ixpback_ids[] = {
	{ "ixp" },
	{ "" }
};


static struct xenbus_driver ixpback = {
	.name = "ixp",
	.owner = THIS_MODULE,
	.ids = ixpback_ids,
	.probe = ixpback_probe,
	.remove = ixpback_remove,
	.otherend_changed = frontend_changed
};


int ixpif_xenbus_init(void)
{
	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	return xenbus_register_backend(&ixpback);
}


/******************************************************************************
 * NOTIFICATION FROM GUEST OS.
 */

static void ixpif_notify_work(ixpif_t *ixpif)
{
	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	ixpif->waiting_reqs = 1;
	wake_up(&ixpif->wq);
}

irqreturn_t ixpif_be_int(int irq, void *dev_id)
{
	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	ixpif_notify_work(dev_id);
	return IRQ_HANDLED;
}



/******************************************************************
 * DOWNWARD CALLS -- These interface with the block-device layer proper.
 */




//
//
//
///******************************************************************
// * MISCELLANEOUS SETUP / TEARDOWN / DEBUGGING
// */
//
//
static void make_response(ixpif_t *ixpif, u64 id,
			    unsigned short op, int st, int resp_size)
{
	struct ixp_response  resp;
	unsigned long     flags;
	int more_to_do = 0;
	int notify;

	resp.id        = id;
	resp.operation = op;
	resp.status    = st;
	resp.resp_size = (uint16_t) resp_size;

	spin_lock_irqsave(&ixpif->ixp_ring_lock, flags);
	
	memcpy(RING_GET_RESPONSE(&ixpif->ixp_ring, ixpif->ixp_ring.rsp_prod_pvt),
		       &resp, sizeof(resp));

	ixpif->ixp_ring.rsp_prod_pvt++;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&ixpif->ixp_ring, notify);
	if (ixpif->ixp_ring.rsp_prod_pvt == ixpif->ixp_ring.req_cons) {
		/*
		 * Tail check for pending requests. Allows frontend to avoid
		 * notifications if requests are already in flight (lower
		 * overheads and promotes batching).
		 */
		RING_FINAL_CHECK_FOR_REQUESTS(&ixpif->ixp_ring, more_to_do);

	} else if (RING_HAS_UNCONSUMED_REQUESTS(&ixpif->ixp_ring)) {
		more_to_do = 1;
	}

	spin_unlock_irqrestore(&ixpif->ixp_ring_lock, flags);

	if (more_to_do)
		ixpif_notify_work(ixpif);
	if (notify)
		notify_remote_via_irq(ixpif->irq);
}

static int __init ixpif_init(void)
{	
	int i, mmap_pages;
	int rc = 0;

	//printk(KERN_ERR " ~-~-~ %s ~-~-~ \n", __FUNCTION__);
	if (!xen_pv_domain())
		return -ENODEV;

	mmap_pages = blkif_reqs * IXPIF_MAX_SEGMENTS_PER_REQUEST;

	pending_reqs          = kmalloc(sizeof(pending_reqs[0]) *
					blkif_reqs, GFP_KERNEL);
	pending_grant_handles = kmalloc(sizeof(pending_grant_handles[0]) *
					mmap_pages, GFP_KERNEL);
	pending_pages         = alloc_empty_pages_and_pagevec(mmap_pages);

	if (ixpback_pagemap_init(mmap_pages))
		goto out_of_memory;

	if (!pending_reqs || !pending_grant_handles || !pending_pages) {
		rc = -ENOMEM;
		goto out_of_memory;
	}

	for (i = 0; i < mmap_pages; i++)
		pending_grant_handles[i] = BLKBACK_INVALID_HANDLE;

	rc = ixpif_interface_init();
	if (rc)
		goto failed_init;

	memset(pending_reqs, 0, sizeof(pending_reqs));
	INIT_LIST_HEAD(&pending_free);

	for (i = 0; i < blkif_reqs; i++)
		list_add_tail(&pending_reqs[i].free_list, &pending_free);

	rc = ixpif_xenbus_init();
	if (rc)
		goto failed_init;

	return 0;

 out_of_memory:
	printk(KERN_ERR "%s: out of memory\n", __func__);
 failed_init:
	kfree(pending_reqs);
	kfree(pending_grant_handles);
	free_empty_pages_and_pagevec(pending_pages, mmap_pages);
	return rc;
}

module_init(ixpif_init);

MODULE_LICENSE("Dual BSD/GPL");
