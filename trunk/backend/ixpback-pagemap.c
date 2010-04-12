#include <linux/module.h>
#include "ixpback-pagemap.h"

static int ixpback_pagemap_size;
static struct ixpback_pagemap *ixpback_pagemap;

static inline int
ixpback_pagemap_entry_clear(struct ixpback_pagemap *map)
{
	static struct ixpback_pagemap zero;
	return !memcmp(map, &zero, sizeof(zero));
}

int
ixpback_pagemap_init(int pages)
{
	ixpback_pagemap = kzalloc(pages * sizeof(struct ixpback_pagemap),
				  GFP_KERNEL);
	if (!ixpback_pagemap)
		return -ENOMEM;

	ixpback_pagemap_size = pages;
	return 0;
}
EXPORT_SYMBOL_GPL(ixpback_pagemap_init);

void
ixpback_pagemap_set(int idx, struct page *page,
		    domid_t domid, busid_t busid, grant_ref_t gref)
{
	struct ixpback_pagemap *entry;

	BUG_ON(!ixpback_pagemap);
	BUG_ON(idx >= ixpback_pagemap_size);

	set_page_private(page, idx);

	entry = ixpback_pagemap + idx;
	if (!ixpback_pagemap_entry_clear(entry)) {
		printk("overwriting pagemap %d: d %u b %u g %u\n",
		       idx, entry->domid, entry->busid, entry->gref);
		BUG();
	}

	entry->page  = page;
	entry->domid = domid;
	entry->busid = busid;
	entry->gref  = gref;
}
EXPORT_SYMBOL_GPL(ixpback_pagemap_set);

void
ixpback_pagemap_clear(struct page *page)
{
	int idx;
	struct ixpback_pagemap *entry;

	idx = (int)page_private(page);

	BUG_ON(!ixpback_pagemap);
	BUG_ON(idx >= ixpback_pagemap_size);

	entry = ixpback_pagemap + idx;
	if (ixpback_pagemap_entry_clear(entry)) {
		printk("clearing empty pagemap %d\n", idx);
		BUG();
	}

	memset(entry, 0, sizeof(*entry));
}
EXPORT_SYMBOL_GPL(ixpback_pagemap_clear);

struct ixpback_pagemap
ixpback_pagemap_read(struct page *page)
{
	int idx;
	struct ixpback_pagemap *entry;

	idx = (int)page_private(page);

	BUG_ON(!ixpback_pagemap);
	BUG_ON(idx >= ixpback_pagemap_size);

	entry = ixpback_pagemap + idx;
	if (ixpback_pagemap_entry_clear(entry)) {
		printk("reading empty pagemap %d\n", idx);
		BUG();
	}

	return *entry;
}
EXPORT_SYMBOL(ixpback_pagemap_read);

MODULE_LICENSE("Dual BSD/GPL");

int
ixpback_pagemap_contains_page(struct page *page)
{
	struct ixpback_pagemap *entry;
	int idx = (int)page_private(page);

	if (idx < 0 || idx >= ixpback_pagemap_size)
		return 0;

	entry = ixpback_pagemap + idx;

	return (entry->page == page);
}
EXPORT_SYMBOL(ixpback_pagemap_contains_page);

