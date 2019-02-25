#ifndef __POSTGRES_H__
#define __POSTGRES_H__
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define elog(err, msg, ...) do { fprintf(stderr, msg, ## __VA_ARGS__); abort(); } while (0)
#define ereport(err, rest) elog(err, "JSON error")
#define Assert(expr) assert(expr)

#define pg_attribute_noreturn() __attribute__((noreturn))

#define unconstify(type, expr) ((type) (expr))

#define check_stack_depth() ((void) 0)

#define PG_UTF8 1
#define GetDatabaseEncoding() PG_UTF8

#define Min(a, b) ((a) < (b) ? (a) : (b))
#define Max(a, b) ((a) > (b) ? (a) : (b))

typedef size_t Size;
typedef int8_t int8;
typedef uint8_t uint8;
typedef int16_t int16;
typedef uint16_t uint16;
typedef int32_t int32;
typedef uint32_t uint32;
typedef int64_t int64;
typedef uint64_t uint64;

typedef uintptr_t Datum;

typedef struct NumericData *Numeric;

#define numeric_is_nan(num) false

#define FLEXIBLE_ARRAY_MEMBER 0

#define MaxAllocSize 0x1000000

typedef union
{
	struct						/* Normal varlena (4-byte length) */
	{
		uint32		va_header;
		char		va_data[FLEXIBLE_ARRAY_MEMBER];
	}			va_4byte;
	struct						/* Compressed-in-line format */
	{
		uint32		va_header;
		uint32		va_rawsize; /* Original data size (excludes header) */
		char		va_data[FLEXIBLE_ARRAY_MEMBER]; /* Compressed data */
	}			va_compressed;
} varattrib_4b;

#define VARHDRSZ			sizeof(uint32)

#define VARSIZE_4B(PTR)		(((varattrib_4b *) (PTR))->va_4byte.va_header & 0x3FFFFFFF)
#define VARDATA_4B(PTR)		(((varattrib_4b *) (PTR))->va_4byte.va_data)
#define SET_VARSIZE_4B(PTR,len)	(((varattrib_4b *) (PTR))->va_4byte.va_header = (len) & 0x3FFFFFFF)

#define VARSIZE_ANY(PTR)	VARSIZE_4B(PTR)
#define VARSIZE(PTR)		VARSIZE_4B(PTR)
#define VARDATA(PTR)		VARDATA_4B(PTR)
#define SET_VARSIZE(PTR, len) SET_VARSIZE_4B(PTR, len)

#define INTALIGN(x) ((x + 3) & ~3)

extern void *palloc(size_t size);
extern void *palloc0(size_t size);
extern void *repalloc(void *p, size_t size);
extern void pfree(void *p);
extern void pool_free();

static inline char *
pstrdup(const char *s)
{
	size_t		len = strlen(s) + 1;

	return (char *) memcpy(palloc(len), s, len);
}

#ifndef __cplusplus
static inline size_t
strnlen(const char *str, size_t maxlen)
{
	const char *p = str;

	while (maxlen-- > 0 && *p)
		p++;
	return p - str;
}
#endif

/*
 * pnstrdup
 *		Like pstrdup(), but append null byte to a
 *		not-necessarily-null-terminated input string.
 */
static inline char *
pnstrdup(const char *in, Size len)
{
	char	   *out;

	len = strnlen(in, len);

	out = (char *) palloc(len + 1);
	memcpy(out, in, len);
	out[len] = '\0';

	return out;
}

typedef int (*qsort_arg_comparator) (const void *a, const void *b, void *arg);
extern void qsort_arg(void *a, size_t n, size_t es, qsort_arg_comparator cmp, void *arg);

#endif /* __POSTGRES_H__ */
