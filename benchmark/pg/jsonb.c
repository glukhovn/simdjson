#include "postgres.h"
#include "json.h"
#include "jsonb.h"
#include "stringinfo.h"

/*
 * Maximum number of elements in an array (or key/value pairs in an object).
 * This is limited by two things: the size of the JEntry array must fit
 * in MaxAllocSize, and the number of elements (or pairs) must fit in the bits
 * reserved for that in the JsonbContainer.header field.
 *
 * (The total size of an array's or object's elements is also limited by
 * JENTRY_OFFLENMASK, but we're not concerned about that here.)
 */
#define JSONB_MAX_ELEMS (Min(MaxAllocSize / sizeof(JsonbValue), JB_CMASK))
#define JSONB_MAX_PAIRS (Min(MaxAllocSize / sizeof(JsonbPair), JB_CMASK))

JsonbValue *
pushJsonbValue(JsonbParseState **pstate, JsonbIteratorToken seq,
			   JsonbValue *jbval);

static void
convertJsonbValue(StringInfo buffer, JEntry *header, JsonbValue *val, int level);

static Numeric
numeric_in(const char *str)
{
	Size		size = VARHDRSZ + strlen(str) + 1;
	char	   *p = (char *) palloc(size);

	SET_VARSIZE(p, size);
	memcpy(VARDATA(p), str, size - VARHDRSZ);

	return (Numeric) p;
}

static const char *
numeric_out(Numeric num)
{
	return pstrdup((const char *) VARDATA(num));
}

typedef struct JsonbInState
{
	JsonbParseState *parseState;
	JsonbValue *res;
} JsonbInState;

static size_t
checkStringLen(size_t len)
{
	if (len > JENTRY_OFFLENMASK)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("string too long to represent as jsonb string"),
				 errdetail("Due to an implementation restriction, jsonb strings cannot exceed %d bytes.",
						   JENTRY_OFFLENMASK)));

	return len;
}

static void
jsonb_in_object_start(void *pstate)
{
	JsonbInState *_state = (JsonbInState *) pstate;

	_state->res = pushJsonbValue(&_state->parseState, WJB_BEGIN_OBJECT, NULL);
}

static void
jsonb_in_object_end(void *pstate)
{
	JsonbInState *_state = (JsonbInState *) pstate;

	_state->res = pushJsonbValue(&_state->parseState, WJB_END_OBJECT, NULL);
}

static void
jsonb_in_array_start(void *pstate)
{
	JsonbInState *_state = (JsonbInState *) pstate;

	_state->res = pushJsonbValue(&_state->parseState, WJB_BEGIN_ARRAY, NULL);
}

static void
jsonb_in_array_end(void *pstate)
{
	JsonbInState *_state = (JsonbInState *) pstate;

	_state->res = pushJsonbValue(&_state->parseState, WJB_END_ARRAY, NULL);
}

static void
jsonb_in_object_field_start(void *pstate, char *fname, bool isnull)
{
	JsonbInState *_state = (JsonbInState *) pstate;
	JsonbValue	v;

	Assert(fname != NULL);
	v.type = jbvString;
	v.val.string.len = checkStringLen(strlen(fname));
	v.val.string.val = fname;

	_state->res = pushJsonbValue(&_state->parseState, WJB_KEY, &v);
}

/*
 * For jsonb we always want the de-escaped value - that's what's in token
 */
static void
jsonb_in_scalar(void *pstate, char *token, JsonTokenType tokentype)
{
	JsonbInState *_state = (JsonbInState *) pstate;
	JsonbValue	v;

	switch (tokentype)
	{

		case JSON_TOKEN_STRING:
			Assert(token != NULL);
			v.type = jbvString;
			v.val.string.len = checkStringLen(strlen(token));
			v.val.string.val = token;
			break;
		case JSON_TOKEN_NUMBER:

			/*
			 * No need to check size of numeric values, because maximum
			 * numeric size is well below the JsonbValue restriction
			 */
			Assert(token != NULL);
			v.type = jbvNumeric;
			v.val.numeric = numeric_in(token);
			break;
		case JSON_TOKEN_TRUE:
			v.type = jbvBool;
			v.val.boolean = true;
			break;
		case JSON_TOKEN_FALSE:
			v.type = jbvBool;
			v.val.boolean = false;
			break;
		case JSON_TOKEN_NULL:
			v.type = jbvNull;
			break;
		default:
			/* should not be possible */
			elog(ERROR, "invalid json token type");
			break;
	}

	if (_state->parseState == NULL)
	{
		/* single scalar */
		JsonbValue	va;

		va.type = jbvArray;
		va.val.array.rawScalar = true;
		va.val.array.nElems = 1;

		_state->res = pushJsonbValue(&_state->parseState, WJB_BEGIN_ARRAY, &va);
		_state->res = pushJsonbValue(&_state->parseState, WJB_ELEM, &v);
		_state->res = pushJsonbValue(&_state->parseState, WJB_END_ARRAY, NULL);
	}
	else
	{
		JsonbValue *o = &_state->parseState->contVal;

		switch (o->type)
		{
			case jbvArray:
				_state->res = pushJsonbValue(&_state->parseState, WJB_ELEM, &v);
				break;
			case jbvObject:
				_state->res = pushJsonbValue(&_state->parseState, WJB_VALUE, &v);
				break;
			default:
				elog(ERROR, "unexpected parent of nested structure");
		}
	}
}

JsonbValue *
jsonb_value_from_cstring(char *json, int len)
{
	JsonLexContext *lex;
	JsonbInState state;
	JsonSemAction sem;

	memset(&state, 0, sizeof(state));
	memset(&sem, 0, sizeof(sem));
	lex = makeJsonLexContextCstringLen(json, len, true);

	sem.semstate = (void *) &state;

	sem.object_start = jsonb_in_object_start;
	sem.array_start = jsonb_in_array_start;
	sem.object_end = jsonb_in_object_end;
	sem.array_end = jsonb_in_array_end;
	sem.scalar = jsonb_in_scalar;
	sem.object_field_start = jsonb_in_object_field_start;

	pg_parse_json(lex, &sem);

	/* after parsing, the item member has the composed jsonb structure */
	return state.res;
}

Jsonb *
jsonb_from_cstring(char *json, int len)
{
	return JsonbValueToJsonb(jsonb_value_from_cstring(json, len));
}

static int
lengthCompareJsonbString(const char *val1, int len1, const char *val2, int len2)
{
	if (len1 == len2)
		return memcmp(val1, val2, len1);
	else
		return len1 > len2 ? 1 : -1;
}

/*
 * Compare two jbvString JsonbValue values, a and b.
 *
 * This is a special qsort() comparator used to sort strings in certain
 * internal contexts where it is sufficient to have a well-defined sort order.
 * In particular, object pair keys are sorted according to this criteria to
 * facilitate cheap binary searches where we don't care about lexical sort
 * order.
 *
 * a and b are first sorted based on their length.  If a tie-breaker is
 * required, only then do we consider string binary equality.
 */
int
lengthCompareJsonbStringValue(const void *a, const void *b)
{
	const JsonbValue *va = (const JsonbValue *) a;
	const JsonbValue *vb = (const JsonbValue *) b;

	Assert(va->type == jbvString);
	Assert(vb->type == jbvString);

	return lengthCompareJsonbString(va->val.string.val, va->val.string.len,
									vb->val.string.val, vb->val.string.len);
}

/*
 * qsort_arg() comparator to compare JsonbPair values.
 *
 * Third argument 'binequal' may point to a bool. If it's set, *binequal is set
 * to true iff a and b have full binary equality, since some callers have an
 * interest in whether the two values are equal or merely equivalent.
 *
 * N.B: String comparisons here are "length-wise"
 *
 * Pairs with equals keys are ordered such that the order field is respected.
 */
static int
lengthCompareJsonbPair(const void *a, const void *b, void *binequal)
{
	const JsonbPair *pa = (const JsonbPair *) a;
	const JsonbPair *pb = (const JsonbPair *) b;
	int			res;

	res = lengthCompareJsonbStringValue(&pa->key, &pb->key);
	if (res == 0 && binequal)
		*((bool *) binequal) = true;

	/*
	 * Guarantee keeping order of equal pair.  Unique algorithm will prefer
	 * first element as value.
	 */
	if (res == 0)
		res = (pa->order > pb->order) ? -1 : 1;

	return res;
}

/*
 * Sort and unique-ify pairs in JsonbValue object
 */
static void
uniqueifyJsonbObject(JsonbValue *object)
{
	bool		hasNonUniq = false;

	Assert(object->type == jbvObject);

	if (!object->val.object.uniquify)
		return;

	if (object->val.object.nPairs > 1)
		qsort_arg(object->val.object.pairs, object->val.object.nPairs, sizeof(JsonbPair),
				  lengthCompareJsonbPair, &hasNonUniq);

	if (hasNonUniq)
	{
		JsonbPair  *ptr = object->val.object.pairs + 1,
				   *res = object->val.object.pairs;

		while (ptr - object->val.object.pairs < object->val.object.nPairs)
		{
			/* Avoid copying over duplicate */
			if (lengthCompareJsonbStringValue(ptr, res) != 0)
			{
				res++;
				if (ptr != res)
					memcpy(res, ptr, sizeof(JsonbPair));
			}
			ptr++;
		}

		object->val.object.nPairs = res + 1 - object->val.object.pairs;
	}
}


/*
 * pushJsonbValue() worker:  Iteration-like forming of Jsonb
 */
static JsonbParseState *
pushState(JsonbParseState **pstate)
{
	JsonbParseState *ns = (JsonbParseState *) palloc(sizeof(JsonbParseState));

	ns->next = *pstate;
	return ns;
}

/*
 * pushJsonbValue() worker:  Append a pair key to state when generating a Jsonb
 */
static void
appendKey(JsonbParseState *pstate, JsonbValue *string)
{
	JsonbValue *object = &pstate->contVal;

	Assert(object->type == jbvObject);
	Assert(string->type == jbvString);

	if (object->val.object.nPairs >= (int) JSONB_MAX_PAIRS)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("number of jsonb object pairs exceeds the maximum allowed (%zu)",
						JSONB_MAX_PAIRS)));

	if (object->val.object.nPairs >= (int) pstate->size)
	{
		pstate->size *= 2;
		object->val.object.pairs = (JsonbPair *) repalloc(object->val.object.pairs,
											sizeof(JsonbPair) * pstate->size);
	}

	object->val.object.pairs[object->val.object.nPairs].key = *string;
	object->val.object.pairs[object->val.object.nPairs].order = object->val.object.nPairs;
}

/*
 * pushJsonbValue() worker:  Append a pair value to state when generating a
 * Jsonb
 */
static void
appendValue(JsonbParseState *pstate, JsonbValue *scalarVal)
{
	JsonbValue *object = &pstate->contVal;

	Assert(object->type == jbvObject);

	object->val.object.pairs[object->val.object.nPairs++].value = *scalarVal;
}

/*
 * pushJsonbValue() worker:  Append an element to state when generating a Jsonb
 */
static void
appendElement(JsonbParseState *pstate, JsonbValue *scalarVal)
{
	JsonbValue *array = &pstate->contVal;

	Assert(array->type == jbvArray);

	if (array->val.array.nElems >= (int) JSONB_MAX_ELEMS)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("number of jsonb array elements exceeds the maximum allowed (%zu)",
						JSONB_MAX_ELEMS)));

	if (array->val.array.nElems >= (int) pstate->size)
	{
		pstate->size *= 2;
		array->val.array.elems = (JsonbValue *) repalloc(array->val.array.elems,
										  sizeof(JsonbValue) * pstate->size);
	}

	array->val.array.elems[array->val.array.nElems++] = *scalarVal;
}

/*
 * Do the actual pushing, with only scalar or pseudo-scalar-array values
 * accepted.
 */
JsonbValue *
pushJsonbValueScalar(JsonbParseState **pstate, JsonbIteratorToken seq,
					 JsonbValue *scalarVal)
{
	JsonbValue *result = NULL;

	switch (seq)
	{
		case WJB_BEGIN_ARRAY:
			Assert(!scalarVal || scalarVal->val.array.rawScalar);
			*pstate = pushState(pstate);
			result = &(*pstate)->contVal;
			(*pstate)->contVal.type = jbvArray;
			(*pstate)->contVal.val.array.nElems = 0;
			(*pstate)->contVal.val.array.rawScalar = (scalarVal &&
													  scalarVal->val.array.rawScalar);
			if (scalarVal && scalarVal->val.array.nElems > 0)
			{
				/* Assume that this array is still really a scalar */
				Assert(scalarVal->type == jbvArray);
				(*pstate)->size = scalarVal->val.array.nElems;
			}
			else
			{
				(*pstate)->size = 4;
			}
			(*pstate)->contVal.val.array.elems = (JsonbValue*) palloc(sizeof(JsonbValue) *
														(*pstate)->size);
			break;
		case WJB_BEGIN_OBJECT:
			Assert(!scalarVal);
			*pstate = pushState(pstate);
			result = &(*pstate)->contVal;
			(*pstate)->contVal.type = jbvObject;
			(*pstate)->contVal.val.object.nPairs = 0;
			(*pstate)->size = 4;
			(*pstate)->contVal.val.object.pairs = (JsonbPair *) palloc(sizeof(JsonbPair) *
														 (*pstate)->size);
			(*pstate)->contVal.val.object.uniquify = true;
			break;
		case WJB_KEY:
			Assert(scalarVal->type == jbvString);
			appendKey(*pstate, scalarVal);
			break;
		case WJB_VALUE:
			Assert(IsAJsonbScalar(scalarVal));
			appendValue(*pstate, scalarVal);
			break;
		case WJB_ELEM:
			Assert(IsAJsonbScalar(scalarVal));
			appendElement(*pstate, scalarVal);
			break;
		case WJB_END_OBJECT:
			uniqueifyJsonbObject(&(*pstate)->contVal);
			/* fall through! */
		case WJB_END_ARRAY:
			/* Steps here common to WJB_END_OBJECT case */
			Assert(!scalarVal);
			result = &(*pstate)->contVal;

			/*
			 * Pop stack and push current array/object as value in parent
			 * array/object
			 */
			*pstate = (*pstate)->next;
			if (*pstate)
			{
				switch ((*pstate)->contVal.type)
				{
					case jbvArray:
						appendElement(*pstate, result);
						break;
					case jbvObject:
						appendValue(*pstate, result);
						break;
					default:
						elog(ERROR, "invalid jsonb container type");
				}
			}
			break;
		default:
			elog(ERROR, "unrecognized jsonb sequential processing token");
	}

	return result;
}

/*
 * Push JsonbValue into JsonbParseState.
 *
 * Used when parsing JSON tokens to form Jsonb, or when converting an in-memory
 * JsonbValue to a Jsonb.
 *
 * Initial state of *JsonbParseState is NULL, since it'll be allocated here
 * originally (caller will get JsonbParseState back by reference).
 *
 * Only sequential tokens pertaining to non-container types should pass a
 * JsonbValue.  There is one exception -- WJB_BEGIN_ARRAY callers may pass a
 * "raw scalar" pseudo array to append it - the actual scalar should be passed
 * next and it will be added as the only member of the array.
 *
 * Values of type jvbBinary, which are rolled up arrays and objects,
 * are unpacked before being added to the result.
 */
JsonbValue *
pushJsonbValue(JsonbParseState **pstate, JsonbIteratorToken seq,
			   JsonbValue *jbval)
{
	if (!jbval || (seq != WJB_ELEM && seq != WJB_VALUE) ||
		jbval->type != jbvBinary)
	{
		/* drop through */
		return pushJsonbValueScalar(pstate, seq, jbval);
	}

#if 1
	Assert(0);
	return NULL;
#else
	JsonbIterator *it;
	JsonbValue *res = NULL;
	JsonbValue	v;
	JsonbIteratorToken tok;

	/* unpack the binary and add each piece to the pstate */
	it = JsonbIteratorInit(jbval->val.binary.data);
	while ((tok = JsonbIteratorNext(&it, &v, false)) != WJB_DONE)
		res = pushJsonbValueScalar(pstate, tok,
								   tok < WJB_BEGIN_ARRAY ? &v : NULL);
	return res;
#endif
}

/*
 * Reserve 'len' bytes, at the end of the buffer, enlarging it if necessary.
 * Returns the offset to the reserved area. The caller is expected to fill
 * the reserved area later with copyToBuffer().
 */
static int
reserveFromBuffer(StringInfo buffer, int len)
{
	int			offset;

	/* Make more room if needed */
	enlargeStringInfo(buffer, len);

	/* remember current offset */
	offset = buffer->len;

	/* reserve the space */
	buffer->len += len;

	/*
	 * Keep a trailing null in place, even though it's not useful for us; it
	 * seems best to preserve the invariants of StringInfos.
	 */
	buffer->data[buffer->len] = '\0';

	return offset;
}

/*
 * Copy 'len' bytes to a previously reserved area in buffer.
 */
static void
copyToBuffer(StringInfo buffer, int offset, const char *data, int len)
{
	memcpy(buffer->data + offset, data, len);
}

/*
 * A shorthand for reserveFromBuffer + copyToBuffer.
 */
static void
appendToBuffer(StringInfo buffer, const char *data, int len)
{
	int			offset;

	offset = reserveFromBuffer(buffer, len);
	copyToBuffer(buffer, offset, data, len);
}


/*
 * Append padding, so that the length of the StringInfo is int-aligned.
 * Returns the number of padding bytes appended.
 */
static short
padBufferToInt(StringInfo buffer)
{
	int			padlen,
				p,
				offset;

	padlen = INTALIGN(buffer->len) - buffer->len;

	offset = reserveFromBuffer(buffer, padlen);

	/* padlen must be small, so this is probably faster than a memset */
	for (p = 0; p < padlen; p++)
		buffer->data[offset + p] = '\0';

	return padlen;
}

/*
 * Given a JsonbValue, convert to Jsonb. The result is palloc'd.
 */
static Jsonb *
convertToJsonb(JsonbValue *val)
{
	StringInfoData buffer;
	JEntry		jentry;
	Jsonb	   *res;

	/* Should not already have binary representation */
	Assert(val->type != jbvBinary);

	/* Allocate an output buffer. It will be enlarged as needed */
	initStringInfo(&buffer);

	/* Make room for the varlena header */
	reserveFromBuffer(&buffer, VARHDRSZ);

	convertJsonbValue(&buffer, &jentry, val, 0);

	/*
	 * Note: the JEntry of the root is discarded. Therefore the root
	 * JsonbContainer struct must contain enough information to tell what kind
	 * of value it is.
	 */

	res = (Jsonb *) buffer.data;

	SET_VARSIZE(res, buffer.len);

	return res;
}

static void
convertJsonbScalar(StringInfo buffer, JEntry *jentry, JsonbValue *scalarVal)
{
	int			numlen;
	short		padlen;

	switch (scalarVal->type)
	{
		case jbvNull:
			*jentry = JENTRY_ISNULL;
			break;

		case jbvString:
			appendToBuffer(buffer, scalarVal->val.string.val, scalarVal->val.string.len);

			*jentry = scalarVal->val.string.len;
			break;

		case jbvNumeric:
			/* replace numeric NaN with string "NaN" */
			if (numeric_is_nan(scalarVal->val.numeric))
			{
				appendToBuffer(buffer, "NaN", 3);
				*jentry = scalarVal->val.string.len;
				break;
			}

			numlen = VARSIZE_ANY(scalarVal->val.numeric);
			padlen = padBufferToInt(buffer);


			appendToBuffer(buffer, (char *) scalarVal->val.numeric, numlen);

			*jentry = JENTRY_ISNUMERIC | (padlen + numlen);
			break;

		case jbvBool:
			*jentry = (scalarVal->val.boolean) ?
				JENTRY_ISBOOL_TRUE : JENTRY_ISBOOL_FALSE;
			break;

		default:
			elog(ERROR, "invalid jsonb scalar type");
	}
}

static void
convertJsonbArray(StringInfo buffer, JEntry *pheader, JsonbValue *val, int level)
{
	int			base_offset;
	int			jentry_offset;
	int			i;
	int			totallen;
	uint32		header;
	int			nElems = val->val.array.nElems;

	/* Remember where in the buffer this array starts. */
	base_offset = buffer->len;

	/* Align to 4-byte boundary (any padding counts as part of my data) */
	padBufferToInt(buffer);

	/*
	 * Construct the header Jentry and store it in the beginning of the
	 * variable-length payload.
	 */
	header = nElems | JB_FARRAY;
	if (val->val.array.rawScalar)
	{
		Assert(nElems == 1);
		Assert(level == 0);
		header |= JB_FSCALAR;
	}

	appendToBuffer(buffer, (char *) &header, sizeof(uint32));

	/* Reserve space for the JEntries of the elements. */
	jentry_offset = reserveFromBuffer(buffer, sizeof(JEntry) * nElems);

	totallen = 0;
	for (i = 0; i < nElems; i++)
	{
		JsonbValue *elem = &val->val.array.elems[i];
		int			len;
		JEntry		meta;

		/*
		 * Convert element, producing a JEntry and appending its
		 * variable-length data to buffer
		 */
		convertJsonbValue(buffer, &meta, elem, level + 1);

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereport(ERROR,
					(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
					 errmsg("total size of jsonb array elements exceeds the maximum of %u bytes",
							JENTRY_OFFLENMASK)));

		/*
		 * Convert each JB_OFFSET_STRIDE'th length to an offset.
		 */
		if ((i % JB_OFFSET_STRIDE) == 0)
			meta = (meta & JENTRY_TYPEMASK) | totallen | JENTRY_HAS_OFF;

		copyToBuffer(buffer, jentry_offset, (char *) &meta, sizeof(JEntry));
		jentry_offset += sizeof(JEntry);
	}

	/* Total data size is everything we've appended to buffer */
	totallen = buffer->len - base_offset;

	/* Check length again, since we didn't include the metadata above */
	if (totallen > JENTRY_OFFLENMASK)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("total size of jsonb array elements exceeds the maximum of %u bytes",
						JENTRY_OFFLENMASK)));

	/* Initialize the header of this node in the container's JEntry array */
	*pheader = JENTRY_ISCONTAINER | totallen;
}

static void
convertJsonbObject(StringInfo buffer, JEntry *pheader, JsonbValue *val, int level)
{
	int			base_offset;
	int			jentry_offset;
	int			i;
	int			totallen;
	uint32		header;
	int			nPairs = val->val.object.nPairs;

	/* Remember where in the buffer this object starts. */
	base_offset = buffer->len;

	/* Align to 4-byte boundary (any padding counts as part of my data) */
	padBufferToInt(buffer);

	/*
	 * Construct the header Jentry and store it in the beginning of the
	 * variable-length payload.
	 */
	header = nPairs | JB_FOBJECT;
	appendToBuffer(buffer, (char *) &header, sizeof(uint32));

	/* Reserve space for the JEntries of the keys and values. */
	jentry_offset = reserveFromBuffer(buffer, sizeof(JEntry) * nPairs * 2);

	/*
	 * Iterate over the keys, then over the values, since that is the ordering
	 * we want in the on-disk representation.
	 */
	totallen = 0;
	for (i = 0; i < nPairs; i++)
	{
		JsonbPair  *pair = &val->val.object.pairs[i];
		int			len;
		JEntry		meta;

		/*
		 * Convert key, producing a JEntry and appending its variable-length
		 * data to buffer
		 */
		convertJsonbScalar(buffer, &meta, &pair->key);

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereport(ERROR,
					(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
					 errmsg("total size of jsonb object elements exceeds the maximum of %u bytes",
							JENTRY_OFFLENMASK)));

		/*
		 * Convert each JB_OFFSET_STRIDE'th length to an offset.
		 */
		if ((i % JB_OFFSET_STRIDE) == 0)
			meta = (meta & JENTRY_TYPEMASK) | totallen | JENTRY_HAS_OFF;

		copyToBuffer(buffer, jentry_offset, (char *) &meta, sizeof(JEntry));
		jentry_offset += sizeof(JEntry);
	}
	for (i = 0; i < nPairs; i++)
	{
		JsonbPair  *pair = &val->val.object.pairs[i];
		int			len;
		JEntry		meta;

		/*
		 * Convert value, producing a JEntry and appending its variable-length
		 * data to buffer
		 */
		convertJsonbValue(buffer, &meta, &pair->value, level + 1);

		len = JBE_OFFLENFLD(meta);
		totallen += len;

		/*
		 * Bail out if total variable-length data exceeds what will fit in a
		 * JEntry length field.  We check this in each iteration, not just
		 * once at the end, to forestall possible integer overflow.
		 */
		if (totallen > JENTRY_OFFLENMASK)
			ereport(ERROR,
					(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
					 errmsg("total size of jsonb object elements exceeds the maximum of %u bytes",
							JENTRY_OFFLENMASK)));

		/*
		 * Convert each JB_OFFSET_STRIDE'th length to an offset.
		 */
		if (((i + nPairs) % JB_OFFSET_STRIDE) == 0)
			meta = (meta & JENTRY_TYPEMASK) | totallen | JENTRY_HAS_OFF;

		copyToBuffer(buffer, jentry_offset, (char *) &meta, sizeof(JEntry));
		jentry_offset += sizeof(JEntry);
	}

	/* Total data size is everything we've appended to buffer */
	totallen = buffer->len - base_offset;

	/* Check length again, since we didn't include the metadata above */
	if (totallen > JENTRY_OFFLENMASK)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("total size of jsonb object elements exceeds the maximum of %u bytes",
						JENTRY_OFFLENMASK)));

	/* Initialize the header of this node in the container's JEntry array */
	*pheader = JENTRY_ISCONTAINER | totallen;
}

/*
 * Subroutine of convertJsonb: serialize a single JsonbValue into buffer.
 *
 * The JEntry header for this node is returned in *header.  It is filled in
 * with the length of this value and appropriate type bits.  If we wish to
 * store an end offset rather than a length, it is the caller's responsibility
 * to adjust for that.
 *
 * If the value is an array or an object, this recurses. 'level' is only used
 * for debugging purposes.
 */
static void
convertJsonbValue(StringInfo buffer, JEntry *header, JsonbValue *val, int level)
{
	check_stack_depth();

	if (!val)
		return;

	/*
	 * A JsonbValue passed as val should never have a type of jbvBinary, and
	 * neither should any of its sub-components. Those values will be produced
	 * by convertJsonbArray and convertJsonbObject, the results of which will
	 * not be passed back to this function as an argument.
	 */

	if (IsAJsonbScalar(val))
		convertJsonbScalar(buffer, header, val);
	else if (val->type == jbvArray)
		convertJsonbArray(buffer, header, val, level);
	else if (val->type == jbvObject)
		convertJsonbObject(buffer, header, val, level);
	else
		elog(ERROR, "unknown type of jsonb container to convert");
}

/*
 * Turn an in-memory JsonbValue into a Jsonb for on-disk storage.
 *
 * There isn't a JsonbToJsonbValue(), because generally we find it more
 * convenient to directly iterate through the Jsonb representation and only
 * really convert nested scalar values.  JsonbIteratorNext() does this, so that
 * clients of the iteration code don't have to directly deal with the binary
 * representation (JsonbDeepContains() is a notable exception, although all
 * exceptions are internal to this module).  In general, functions that accept
 * a JsonbValue argument are concerned with the manipulation of scalar values,
 * or simple containers of scalar values, where it would be inconvenient to
 * deal with a great amount of other state.
 */
Jsonb *
JsonbValueToJsonb(JsonbValue *val)
{
	Jsonb	   *out;

	if (IsAJsonbScalar(val))
	{
		/* Scalar value */
		JsonbParseState *pstate = NULL;
		JsonbValue *res;
		JsonbValue	scalarArray;

		scalarArray.type = jbvArray;
		scalarArray.val.array.rawScalar = true;
		scalarArray.val.array.nElems = 1;

		pushJsonbValue(&pstate, WJB_BEGIN_ARRAY, &scalarArray);
		pushJsonbValue(&pstate, WJB_ELEM, val);
		res = pushJsonbValue(&pstate, WJB_END_ARRAY, NULL);

		out = convertToJsonb(res);
	}
	else if (val->type == jbvObject || val->type == jbvArray)
	{
		out = convertToJsonb(val);
	}
	else
	{
		Assert(val->type == jbvBinary);
		out = (Jsonb *) palloc(VARHDRSZ + val->val.binary.len);
		SET_VARSIZE(out, VARHDRSZ + val->val.binary.len);
		memcpy(VARDATA(out), val->val.binary.data, val->val.binary.len);
	}

	return out;
}
