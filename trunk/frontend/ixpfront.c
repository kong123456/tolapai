/*   
 * ixpfront.c
 *
 * XenLinux tolapai frontend driver.
 * Modified from xen block device driver
 * 
 * Author: venkat (venkatraghavan@gatech.edu)  
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

#include <linux/interrupt.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/cdrom.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

#include <xen/xenbus.h>
#include <xen/grant_table.h>
#include <xen/events.h>
#include <xen/page.h>
#include <xen/interface/grant_table.h>
#include <xen/interface/io/protocols.h>
#include <asm/xen/hypervisor.h>

#include <ixp_common.h>
#include <frontend/wrapper.h>

enum ixp_state {
	IXP_STATE_DISCONNECTED,
	IXP_STATE_CONNECTED,
	IXP_STATE_SUSPENDED,
};

struct ixp_shadow {
	struct ixp_request req;
	void *req_page;
        cb_params_t r_params;
	unsigned long frame[IXPIF_MAX_SEGMENTS_PER_REQUEST];
};


#define IXP_RING_SIZE __RING_SIZE((struct ixp_sring *)0, PAGE_SIZE)

/*
 * We have one of these per vbd, whether ide, scsi or 'other'.  They
 * hang in private_data off the gendisk structure. We may end up
 * putting all kinds of interesting stuff here :-)
 */
struct ixpfront_info
{
	struct xenbus_device *xbdev;
	int vdevice;
	ixp_vdev_t handle;
	enum ixp_state connected;
	int ring_ref;
	struct ixp_front_ring ring;
	unsigned int evtchn, irq;
	struct ixp_shadow shadow[IXP_RING_SIZE];
	unsigned long shadow_free;

	libcb_t app_cb;
	int is_ready;

	/**
	 * The number of people holding this device open.  We won't allow a
	 * hot-unplug unless this is 0.
	 */
	int users;
};


#define MAXIMUM_OUTSTANDING_BLOCK_REQS \
	(IXPIF_MAX_SEGMENTS_PER_REQUEST * IXP_RING_SIZE)
#define GRANT_INVALID_REF	0

#define DEV_NAME	"ixp"	/* name in /dev */

static int get_id_from_freelist(struct ixpfront_info *info)
{
	unsigned long free = info->shadow_free;
	BUG_ON(free >= IXP_RING_SIZE);
	info->shadow_free = info->shadow[free].req.id;
	info->shadow[free].req.id = 0x0fffffee; /* debug */
	return free;
}


static void add_id_to_freelist(struct ixpfront_info *info,
			       unsigned long id)
{
	info->shadow[id].req.id  = info->shadow_free;
	//info->shadow[id].request = 0;
	info->shadow_free = id;
}

static inline void flush_requests(struct ixpfront_info *info)
{
	int notify;

	//printk(KERN_ERR "%s: pushing requests\n", __FUNCTION__);

	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->ring, notify);

	if (notify) {
		notify_remote_via_irq(info->irq);
	}
}


/*
 * blkif_queue_request
 *
 * request block io
 *
 * id: for guest use only.
 * operation: BLKIF_OP_{READ,WRITE,PROBE}
 * buffer: buffer to read/write into. this should be a
 *   virtual address in the guest os.
 */
int ixp_queue_request(struct app_request *app_req, void *metadata)
{
	struct ixpfront_info *info = (struct ixpfront_info *) metadata;
	unsigned long buffer_mfn;
	struct ixp_request *ring_req;
  	char *req_page = 0, *curr_pos;
	unsigned long id;
	int ref, err;
	grant_ref_t gref_head;

	if (unlikely(info->connected != IXP_STATE_CONNECTED))
		return 1;

  	if (RING_FULL(&info->ring)) {
		printk(KERN_ERR "%s:Ring full - returning backpressure\n", __FUNCTION__);
		return 1;
	}

	if (gnttab_alloc_grant_references(
		IXPIF_MAX_SEGMENTS_PER_REQUEST, &gref_head) < 0) {
		/*gnttab_request_free_callback(
			&info->callback,
			ixp_restart_queue_callback,
			info,
			IXP_MAX_SEGMENTS_PER_REQUEST);*/
		return 1; 
	}

	/* Fill out a communications ring structure. */
	ring_req = RING_GET_REQUEST(&info->ring, info->ring.req_prod_pvt);
	id = get_id_from_freelist(info);

	ring_req->id = id;
	ring_req->handle = info->handle;

	ring_req->operation = IXP_OP_3DES_ENCRYPT;

	ring_req->nr_segments = 1;
	BUG_ON(ring_req->nr_segments > IXPIF_MAX_SEGMENTS_PER_REQUEST);

	req_page = (char *)__get_free_page(GFP_NOIO | __GFP_HIGH);

	if(req_page == 0) {
	  printk(KERN_ERR "ixp_queue_request:Error allocating memory");
	  return 1;
	}

	((struct des_request *)req_page)->key_size = app_req->key_size;
	((struct des_request *)req_page)->iv_size = app_req->iv_size;
	((struct des_request *)req_page)->msg_size = app_req->msg_size;

	curr_pos = req_page + sizeof(struct des_request);
	memcpy(curr_pos, app_req->key, app_req->key_size);
	curr_pos += app_req->key_size;

	memcpy(curr_pos, app_req->iv, app_req->iv_size);
	curr_pos += app_req->iv_size;

	memcpy(curr_pos, app_req->msg, app_req->msg_size);
	curr_pos += app_req->msg_size;

	buffer_mfn = virt_to_mfn(req_page);

 	/* install a grant reference. */
	ref = gnttab_claim_grant_reference(&gref_head);
  	BUG_ON(ref == -ENOSPC);

	gnttab_grant_foreign_access_ref(
	      ref,
	      info->xbdev->otherend_id,
	      buffer_mfn,
	      0);
	
	info->shadow[id].r_params.presp = app_req->presp;
	info->shadow[id].r_params.callbk_tag = app_req->callbk_tag;
	info->shadow[id].frame[0] = mfn_to_pfn(buffer_mfn);
	info->shadow[id].req_page = req_page;

	ring_req->seg[0] =
	      (struct ixp_request_segment) {
		.gref       = ref
	      };

	info->ring.req_prod_pvt++;

	/* Keep a private copy so we can reissue requests when recovering. */
	info->shadow[id].req = *ring_req;

  	flush_requests(info);

	//gnttab_free_grant_references(gref_head);

	return 0;
}


EXPORT_SYMBOL(ixp_queue_request);

static void ixp_free(struct ixpfront_info *info, int suspend)
{
	/* Prevent new requests being issued until we fix things up. */
	info->connected = suspend ?
	IXP_STATE_SUSPENDED : IXP_STATE_DISCONNECTED;
	
	/* Free resources associated with old device channel. */
	if (info->ring_ref != GRANT_INVALID_REF) {
		gnttab_end_foreign_access(info->ring_ref, 0,
					  (unsigned long)info->ring.sring);
		info->ring_ref = GRANT_INVALID_REF;
		info->ring.sring = NULL;
	}
	if (info->irq)
		unbind_from_irqhandler(info->irq, info);
	info->evtchn = info->irq = 0;

}

void dump_message(char *msg,unsigned int size) {
  int i = 0, j = 0;

  printk(KERN_ERR "dump: size -- %d\n", size);
  
  i = size / 4;

  for(j = 0; j < i; j++) {
    printk(KERN_ERR "0x%04x: 0x%08X\n", j*4, *(unsigned int *)&msg[j * 4]);
  }  
  
}


static void ixp_completion(struct ixp_shadow *s)
{
	int i;
	for (i = 0; i < s->req.nr_segments; i++)
		gnttab_end_foreign_access(s->req.seg[i].gref, 0, 0UL);
	
	free_page(s->req_page);
	s->req_page = NULL;
}

static void ixp_install_response(struct ixpfront_info *info, struct ixp_response *iresp) {
  	struct app_response aresp;
	char *rsp_ptr = NULL, *dst_ptr = NULL;
	int offset = 0, msg_size = 0;

        aresp.status = iresp->status;
	
	/* Copy response here into r_params.presp */
	rsp_ptr = mfn_to_virt(pfn_to_mfn(info->shadow[iresp->id].frame[0]));

	if(rsp_ptr == NULL) 
	  printk(KERN_ERR "pfn_to_virt returned NULL\n");
		
	dst_ptr = info->shadow[iresp->id].r_params.presp;
	
	msg_size = ((struct des_request *)rsp_ptr)->msg_size;
	offset = sizeof(struct des_request) + ((struct des_request *)rsp_ptr)->key_size + ((struct des_request *)rsp_ptr)->iv_size;

	rsp_ptr += offset;

	memcpy(dst_ptr, rsp_ptr, msg_size);

        info->app_cb(info->shadow[iresp->id].r_params.callbk_tag, &aresp);	

	return; 
}

static irqreturn_t ixp_interrupt(int irq, void *dev_id)
{
	struct ixp_response *bret;
	RING_IDX i, rp;
	struct ixpfront_info *info = (struct ixpfront_info *)dev_id;
	int error;


	if (unlikely(info->connected != IXP_STATE_CONNECTED)) {
		return IRQ_HANDLED;
	}

 again:
	rp = info->ring.sring->rsp_prod;
	rmb(); /* Ensure we see queued responses up to 'rp'. */

	for (i = info->ring.rsp_cons; i != rp; i++) {
		unsigned long id;

		bret = RING_GET_RESPONSE(&info->ring, i);
		id   = bret->id;
		
		ixp_install_response(info, bret);
    		ixp_completion(&info->shadow[id]);

		add_id_to_freelist(info, id);

		error = (bret->status == IXPIF_RSP_OKAY) ? 0 : -EIO;
		switch (bret->operation) {
		case IXP_OP_3DES_ENCRYPT:
			if (unlikely(bret->status != IXPIF_RSP_OKAY))
				dev_dbg(&info->xbdev->dev, "Bad return from blkdev data "
					"request: %x\n", bret->status);

			break;
		default:
			BUG();
		}
	}

	info->ring.rsp_cons = i;

	if (i != info->ring.req_prod_pvt) {
		int more_to_do;
		RING_FINAL_CHECK_FOR_RESPONSES(&info->ring, more_to_do);
		if (more_to_do)
			goto again;
	} else
		info->ring.sring->rsp_event = i + 1;

	return IRQ_HANDLED;
}


static int setup_ixpring(struct xenbus_device *dev,
			 struct ixpfront_info *info)
{
	struct ixp_sring *sring;
	int err;

	info->ring_ref = GRANT_INVALID_REF;

	sring = (struct ixp_sring *)__get_free_page(GFP_NOIO | __GFP_HIGH);
	if (!sring) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating shared ring");
		return -ENOMEM;
	}
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&info->ring, sring, PAGE_SIZE);

	err = xenbus_grant_ring(dev, virt_to_mfn(info->ring.sring));
	if (err < 0) {
		free_page((unsigned long)sring);
		info->ring.sring = NULL;
		goto fail;
	}
	
  	info->ring_ref = err;

	err = xenbus_alloc_evtchn(dev, &info->evtchn);
	if (err)
		goto fail;

	err = bind_evtchn_to_irqhandler(info->evtchn,
					ixp_interrupt,
					IRQF_SAMPLE_RANDOM, "ixp", info);
	if (err <= 0) {
		xenbus_dev_fatal(dev, err,
				 "bind_evtchn_to_irqhandler failed");
		goto fail;
	}
	info->irq = err;

	return 0;
fail:
	ixp_free(info, 0);
	return err;
}


/* Common code used when first setting up, and when resuming. */
static int talk_to_ixpback(struct xenbus_device *dev,
			   struct ixpfront_info *info)
{
	const char *message = NULL;
	struct xenbus_transaction xbt;
	int err;

	/* Create shared ring, alloc event channel. */
	err = setup_ixpring(dev, info);
	if (err)
		goto out;

again:
	err = xenbus_transaction_start(&xbt);
	if (err) {
		xenbus_dev_fatal(dev, err, "starting transaction");
		goto destroy_ixpring;
	}

	err = xenbus_printf(xbt, dev->nodename,
			    "ring-ref", "%u", info->ring_ref);
	if (err) {
		message = "writing ring-ref";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename,
			    "event-channel", "%u", info->evtchn);
	if (err) {
		message = "writing event-channel";
		goto abort_transaction;
	}
	err = xenbus_printf(xbt, dev->nodename, "protocol", "%s",
			    XEN_IO_PROTO_ABI_NATIVE);
	if (err) {
		message = "writing protocol";
		goto abort_transaction;
	}

	err = xenbus_transaction_end(xbt, 0);
	if (err) {
		if (err == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto destroy_ixpring;
	}

	xenbus_switch_state(dev, XenbusStateInitialised);

	return 0;

 abort_transaction:
	xenbus_transaction_end(xbt, 1);
	if (message)
		xenbus_dev_fatal(dev, err, "%s", message);
 destroy_ixpring:
	ixp_free(info, 0);
 out:
	return err;
}


/**
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures and the ring buffer for communication with the backend, and
 * inform the backend of the appropriate details for those.  Switch to
 * Initialised state.
 */
static int ixpfront_probe(struct xenbus_device *dev,
			  const struct xenbus_device_id *id)
{
	int err, vdevice, i;
	struct ixpfront_info *info;

	/* FIXME: Use dynamic device id if this is not set. */
	err = xenbus_scanf(XBT_NIL, dev->nodename,
			   "virtual-device", "%i", &vdevice);
	if (err != 1) {
		/* go looking in the extended area instead */
		err = xenbus_scanf(XBT_NIL, dev->nodename, "virtual-device-ext",
				   "%i", &vdevice);
		if (err != 1) {
			xenbus_dev_fatal(dev, err, "reading virtual-device");
			return err;
		}
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating info structure");
		return -ENOMEM;
	}

	info->xbdev = dev;
	info->vdevice = vdevice;
	info->connected = IXP_STATE_DISCONNECTED;

	for (i = 0; i < IXP_RING_SIZE; i++)
		info->shadow[i].req.id = i+1;
	info->shadow[IXP_RING_SIZE-1].req.id = 0x0fffffff;

	/* Front end dir is a number, which is used as the id. */
	info->handle = simple_strtoul(strrchr(dev->nodename, '/')+1, NULL, 0);
	dev_set_drvdata(&dev->dev, info);

	err = talk_to_ixpback(dev, info);
	if (err) {
		kfree(info);
		dev_set_drvdata(&dev->dev, NULL);
		return err;
	}

	return 0;
}


static int ixp_recover(struct ixpfront_info *info)
{
	int i;
	struct ixp_request *req;
	struct ixp_shadow *copy;
	int j;

	/* Stage 1: Make a safe copy of the shadow state. */
	copy = kmalloc(sizeof(info->shadow),
		       GFP_NOIO | __GFP_REPEAT | __GFP_HIGH);
	if (!copy)
		return -ENOMEM;
	memcpy(copy, info->shadow, sizeof(info->shadow));

	/* Stage 2: Set up free list. */
	memset(&info->shadow, 0, sizeof(info->shadow));
	for (i = 0; i < IXP_RING_SIZE; i++)
		info->shadow[i].req.id = i+1;
	info->shadow_free = info->ring.req_prod_pvt;
	info->shadow[IXP_RING_SIZE-1].req.id = 0x0fffffff;

	/* Stage 3: Find pending requests and requeue them. */
	for (i = 0; i < IXP_RING_SIZE; i++) {
		/* Not in use? */
		if (copy[i].req_page == NULL)
			continue;

		/* Grab a request slot and copy shadow state into it. */
		req = RING_GET_REQUEST(&info->ring, info->ring.req_prod_pvt);
		*req = copy[i].req;

		/* We get a new request id, and must reset the shadow state. */
		req->id = get_id_from_freelist(info);
		memcpy(&info->shadow[req->id], &copy[i], sizeof(copy[i]));

		/* Rewrite any grant references invalidated by susp/resume. */
		for (j = 0; j < req->nr_segments; j++)
			gnttab_grant_foreign_access_ref(
				req->seg[j].gref,
				info->xbdev->otherend_id,
				pfn_to_mfn(info->shadow[req->id].frame[j]),
				0);
		info->shadow[req->id].req = *req;

		info->ring.req_prod_pvt++;
	}

	kfree(copy);

	xenbus_switch_state(info->xbdev, XenbusStateConnected);

	/* Now safe for us to use the shared ring */
	info->connected = IXP_STATE_CONNECTED;

	/* Send off requeued requests */
	flush_requests(info);

	return 0;
}


/**
 * We are reconnecting to the backend, due to a suspend/resume, or a backend
 * driver restart.  We tear down our blkif structure and recreate it, but
 * leave the device-layer structures intact so that this is transparent to the
 * rest of the kernel.
 */
static int ixpfront_resume(struct xenbus_device *dev)
{
	struct ixpfront_info *info = dev_get_drvdata(&dev->dev);
	int err;

	dev_dbg(&dev->dev, "blkfront_resume: %s\n", dev->nodename);

	ixp_free(info, info->connected == IXP_STATE_CONNECTED);

	err = talk_to_ixpback(dev, info);
	if (info->connected == IXP_STATE_SUSPENDED && !err) {
		err = ixp_recover(info);
	}

	printk(KERN_ERR "Front end driver resuming\n");
	return err;
}


/*
 * Invoked when the backend is finally 'ready' (and has told produced
 * the details about the physical device - #sectors, size, etc).
 */
static void ixpfront_connect(struct ixpfront_info *info)
{

	if ((info->connected == IXP_STATE_CONNECTED) ||
	    (info->connected == IXP_STATE_SUSPENDED) )
		return;

	dev_dbg(&info->xbdev->dev, "%s:%s.\n",
		__func__, info->xbdev->otherend);

	xenbus_switch_state(info->xbdev, XenbusStateConnected);

	info->connected = IXP_STATE_CONNECTED;
	
	init_wrapper_lib((void *)info, &info->app_cb, ixp_queue_request);

        printk(KERN_ERR "ixp front end moved to connected state\n");
	info->is_ready = 1;
}

/**
 * Handle the change of state of the backend to Closing.  We must delete our
 * device-layer structures now, to ensure that writes are flushed through to
 * the backend.  Once is this done, we can switch to Closed in
 * acknowledgement.
 */
static void ixpfront_closing(struct ixpfront_info *info)
{
	/* No more gnttab callback work. */
	//gnttab_cancel_free_callback(&info->callback);

	/* Flush gnttab callback work. Must be done with no locks held. */
	//flush_scheduled_work();
	
	if (info->xbdev)
		xenbus_frontend_closed(info->xbdev);
	printk(KERN_ERR "Closing...\n");
}

/**
 * Callback received when the backend's state changes.
 */
static void ixpback_changed(struct xenbus_device *dev,
			    enum xenbus_state backend_state)
{
	struct ixpfront_info *info = dev_get_drvdata(&dev->dev);

	dev_dbg(&dev->dev, "ixpfront:ixpback_changed to state %d.\n", backend_state);

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitWait:
	case XenbusStateInitialised:
	case XenbusStateReconfiguring:
	case XenbusStateReconfigured:
	case XenbusStateUnknown:
	case XenbusStateClosed:
		break;

	case XenbusStateConnected:
		ixpfront_connect(info);
		break;

	case XenbusStateClosing:
		if (info->users > 0)
			xenbus_dev_error(dev, -EBUSY,
					 "Device in use; refusing to close");
		else
			ixpfront_closing(info);
		break;
	}
}

static int ixpfront_remove(struct xenbus_device *dev)
{
	struct ixpfront_info *info = dev_get_drvdata(&dev->dev);

	dev_dbg(&dev->dev, "blkfront_remove: %s removed\n", dev->nodename);

	ixp_free(info, 0);

	//if(info->users == 0)
		kfree(info);
	//else
	//	info->xbdev = NULL;

	printk(KERN_ERR "Front end driver removed\n");
	return 0;
}

static int ixpfront_is_ready(struct xenbus_device *dev)
{
	struct ixpfront_info *info = dev_get_drvdata(&dev->dev);

	return info->is_ready && info->xbdev;
}

static struct xenbus_device_id ixpfront_ids[] = {
	{ "ixp" },
	{ "" }
};

static struct xenbus_driver ixpfront = {
	.name = "ixp",
	.owner = THIS_MODULE,
	.ids = ixpfront_ids,
	.probe = ixpfront_probe,
	.remove = ixpfront_remove,
	.resume = ixpfront_resume,
	.otherend_changed = ixpback_changed,
	.is_ready = ixpfront_is_ready,
};

static int __init ixpfront_init(void)
{
	if (!xen_domain())
		return -ENODEV;

  printk(KERN_ERR "%s\n", __FUNCTION__);
	return xenbus_register_frontend(&ixpfront);
}
module_init(ixpfront_init);


static void __exit ixpfront_exit(void)
{
  printk(KERN_ERR "%s\n", __FUNCTION__);
	return xenbus_unregister_driver(&ixpfront);
}
module_exit(ixpfront_exit);

MODULE_DESCRIPTION("Xen virtual ixp device frontend");
MODULE_LICENSE("GPL");
//MODULE_ALIAS_BLOCKDEV_MAJOR(XENVBD_MAJOR);
MODULE_ALIAS("xen:ixp");
MODULE_ALIAS("xenixp");


#if 0

static void blkif_restart_queue_callback(void *arg)
{
	struct blkfront_info *info = (struct blkfront_info *)arg;
	schedule_work(&info->work);
}

/*
 * do_blkif_request
 *  read a block; request is in a request queue
 */
static void do_blkif_request(struct request_queue *rq)
{
	struct blkfront_info *info = NULL;
	struct request *req;
	int queued;

	pr_debug("Entered do_blkif_request\n");

	queued = 0;

	while ((req = blk_peek_request(rq)) != NULL) {
		info = req->rq_disk->private_data;

		if (RING_FULL(&info->ring))
			goto wait;

		blk_start_request(req);

		if (!blk_fs_request(req)) {
			__blk_end_request_all(req, -EIO);
			continue;
		}

		pr_debug("do_blk_req %p: cmd %p, sec %lx, "
			 "(%u/%u) buffer:%p [%s]\n",
			 req, req->cmd, (unsigned long)blk_rq_pos(req),
			 blk_rq_cur_sectors(req), blk_rq_sectors(req),
			 req->buffer, rq_data_dir(req) ? "write" : "read");

		if (blkif_queue_request(req)) {
			blk_requeue_request(rq, req);
wait:
			/* Avoid pointless unplugs. */
			blk_stop_queue(rq);
			break;
		}

		queued++;
	}

	if (queued != 0)
		flush_requests(info);
}
static void kick_pending_request_queues(struct blkfront_info *info)
{
	if (!RING_FULL(&info->ring)) {
		/* Re-enable calldowns. */
		blk_start_queue(info->rq);
		/* Kick things off immediately. */
		do_blkif_request(info->rq);
	}
}

static void blkif_restart_queue(struct work_struct *work)
{
	struct blkfront_info *info = container_of(work, struct blkfront_info, work);

	spin_lock_irq(&blkif_io_lock);
	if (info->connected == BLKIF_STATE_CONNECTED)
		kick_pending_request_queues(info);
	spin_unlock_irq(&blkif_io_lock);
}

#endif

