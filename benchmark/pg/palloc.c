#include <stddef.h>
#include "postgres.h"

#if 1
typedef struct PoolPage
{
	struct PoolPage *prev;
	Size		allocated;
	Size		size;
	char		data[FLEXIBLE_ARRAY_MEMBER];
} PoolPage;

static PoolPage *pool;

void *
palloc(size_t size)
{
	size_t		sz = INTALIGN(size + sizeof(uint32));
	char	   *p;

	if (!pool || pool->allocated + sz > pool->size)
	{
		size_t		psz = Max(4096, sz + offsetof(PoolPage, data));
		PoolPage   *page = (PoolPage *) malloc(psz);

		page->prev = pool;
		page->size = psz;
		page->allocated = offsetof(PoolPage, data);

		pool = page;
	}

	p = (char *) pool + pool->allocated;
	*(uint32 *) p = size;
	p += sizeof(uint32);

	pool->allocated += sz;

	return p;
}

void *
palloc0(size_t size)
{
	return memset(palloc(size), 0, size);
}

void *
repalloc(void *p, size_t size)
{
	void	   *p2 = palloc(size);

	if (p)
	{
		size_t		osize = ((uint32 *) p)[-1];
		memcpy(p2, p, Min(osize, size));
	}

	return p2;
}

void
pfree(void *p)
{
}

void
pool_free()
{
	while (pool)
	{
		PoolPage *p = pool;
		pool = p->prev;
		free(p);
	}
}

#else
void *
palloc(size_t size)
{
	return malloc(size);
}

void *
palloc0(size_t size)
{
	return calloc(1, size);
}

void *
repalloc(void *p, size_t size)
{
	return realloc(p, size);
}

void
pfree(void *p)
{
	free(p);
}

void
pool_free()
{
}
#endif
