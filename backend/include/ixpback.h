#ifndef __IXP_BACK_H__
#define __IXP_BACK_H__

#include "ixpback-pagemap.h"
#include <backend/wrapper.h>

struct backend_info;

typedef struct ixpif_st {
	/* Unique identifier for this interface. */
	domid_t           domid;
	unsigned int      handle;
	/* Physical parameters of the comms window. */
	unsigned int      irq;
	/* Comms information. */
	struct ixp_back_ring ixp_ring;
	struct vm_struct *ixp_ring_area;
	
	/* Back pointer to the backend_info. */
	struct backend_info *be;
	
	/* Private fields. */
	spinlock_t       ixp_ring_lock;
	atomic_t         refcnt;

	wait_queue_head_t   wq;
	struct task_struct  *xenblkd;
	unsigned int        waiting_reqs;
	struct request_queue     *plug;

	/* statistics */
//	unsigned long       st_print;
//	int                 st_rd_req;
//	int                 st_wr_req;
	int                 st_oo_req;
//	int                 st_br_req;
//	int                 st_rd_sect;
//	int                 st_wr_sect;

	wait_queue_head_t waiting_to_free;

	grant_handle_t shmem_handle;
	grant_ref_t    shmem_ref;
} ixpif_t;


struct phys_req {
	unsigned short       dev;
	unsigned short       nr_sects;
	struct block_device *bdev;
	blkif_sector_t       sector_number;
};

ixpif_t *ixpif_alloc(domid_t domid);
void ixpif_disconnect(ixpif_t *ixpif);
void ixpif_free(ixpif_t *ixpif);
int ixpif_map(ixpif_t *ixpif, unsigned long shared_page, unsigned int evtchn);

extern int ixpif_interface_init(void);
irqreturn_t ixpif_be_int(int irq, void *dev_id);
int ixpif_schedule(void *arg);


#define blkif_get(_b) (atomic_inc(&(_b)->refcnt))
#define blkif_put(_b)					\
	do {						\
		if (atomic_dec_and_test(&(_b)->refcnt))	\
			wake_up(&(_b)->waiting_to_free);\
	} while (0)



#endif

