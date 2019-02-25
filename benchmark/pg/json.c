/*-------------------------------------------------------------------------
 *
 * json.c
 *		JSON data type support.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/json.c
 *
 *-------------------------------------------------------------------------
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "postgres.h"
#include "stringinfo.h"
#include "json.h"

typedef int pg_wchar;

/*
 * Map a Unicode code point to UTF-8.  utf8string must have 4 bytes of
 * space allocated.
 */
unsigned char *
unicode_to_utf8(pg_wchar c, unsigned char *utf8string)
{
	if (c <= 0x7F)
	{
		utf8string[0] = c;
	}
	else if (c <= 0x7FF)
	{
		utf8string[0] = 0xC0 | ((c >> 6) & 0x1F);
		utf8string[1] = 0x80 | (c & 0x3F);
	}
	else if (c <= 0xFFFF)
	{
		utf8string[0] = 0xE0 | ((c >> 12) & 0x0F);
		utf8string[1] = 0x80 | ((c >> 6) & 0x3F);
		utf8string[2] = 0x80 | (c & 0x3F);
	}
	else
	{
		utf8string[0] = 0xF0 | ((c >> 18) & 0x07);
		utf8string[1] = 0x80 | ((c >> 12) & 0x3F);
		utf8string[2] = 0x80 | ((c >> 6) & 0x3F);
		utf8string[3] = 0x80 | (c & 0x3F);
	}

	return utf8string;
}

/*
 * Return the byte length of a UTF8 character pointed to by s
 *
 * Note: in the current implementation we do not support UTF8 sequences
 * of more than 4 bytes; hence do NOT return a value larger than 4.
 * We return "1" for any leading byte that is either flat-out illegal or
 * indicates a length larger than we support.
 *
 * pg_utf2wchar_with_len(), utf8_to_unicode(), pg_utf8_islegal(), and perhaps
 * other places would need to be fixed to change this.
 */
int
pg_utf_mblen(const unsigned char *s)
{
	int			len;

	if ((*s & 0x80) == 0)
		len = 1;
	else if ((*s & 0xe0) == 0xc0)
		len = 2;
	else if ((*s & 0xf0) == 0xe0)
		len = 3;
	else if ((*s & 0xf8) == 0xf0)
		len = 4;
#ifdef NOT_USED
	else if ((*s & 0xfc) == 0xf8)
		len = 5;
	else if ((*s & 0xfe) == 0xfc)
		len = 6;
#endif
	else
		len = 1;
	return len;
}

/* returns the byte length of a multibyte character */
int
pg_mblen(const char *mbstr)
{
	return pg_utf_mblen((const unsigned char *) mbstr);
}

/*
 * The context of the parser is maintained by the recursive descent
 * mechanism, but is passed explicitly to the error reporting routine
 * for better diagnostics.
 */
typedef enum					/* contexts of JSON parser */
{
	JSON_PARSE_VALUE,			/* expecting a value */
	JSON_PARSE_STRING,			/* expecting a string (for a field name) */
	JSON_PARSE_ARRAY_START,		/* saw '[', expecting value or ']' */
	JSON_PARSE_ARRAY_NEXT,		/* saw array element, expecting ',' or ']' */
	JSON_PARSE_OBJECT_START,	/* saw '{', expecting label or '}' */
	JSON_PARSE_OBJECT_LABEL,	/* saw object label, expecting ':' */
	JSON_PARSE_OBJECT_NEXT,		/* saw object value, expecting ',' or '}' */
	JSON_PARSE_OBJECT_COMMA,	/* saw object ',', expecting next label */
	JSON_PARSE_END				/* saw the end of a document, expect nothing */
} JsonParseContext;

static inline bool json_lex(JsonLexContext *lex);
static inline void json_lex_string(JsonLexContext *lex);
static inline void json_lex_number(JsonLexContext *lex, char *s,
				bool *num_err, int *total_len);
static inline void parse_scalar(JsonLexContext *lex, JsonSemAction *sem);
static bool parse_object_field(JsonLexContext *lex, JsonSemAction *sem);
static void parse_object(JsonLexContext *lex, JsonSemAction *sem);
static bool parse_array_element(JsonLexContext *lex, JsonSemAction *sem);
static void parse_array(JsonLexContext *lex, JsonSemAction *sem);
static void report_parse_error(JsonParseContext ctx, JsonLexContext *lex) pg_attribute_noreturn();
static void report_invalid_token(JsonLexContext *lex) pg_attribute_noreturn();
static char *report_json_context(JsonLexContext *lex);
static char *extract_mb_char(char *s);

/* the null action object used for pure validation */
static JsonSemAction nullSemAction =
{
	NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL
};

/* Recursive Descent parser support routines */

/*
 * lex_peek
 *
 * what is the current look_ahead token?
*/
static inline JsonTokenType
lex_peek(JsonLexContext *lex)
{
	return lex->token_type;
}

/*
 * lex_peek_value
 *
 * get the current look_ahead de-escaped lexeme.
*/
static inline char *
lex_peek_value(JsonLexContext *lex)
{
	if (lex->token_type == JSON_TOKEN_STRING)
		return lex->strval ? pstrdup(lex->strval->data) : NULL;
	else
	{
		int			len = lex->token_terminator - lex->token_start;
		char	   *tokstr = (char *) palloc(len + 1);

		memcpy(tokstr, lex->token_start, len);
		tokstr[len] = '\0';
		return tokstr;
	}
}

static inline bool
lex_set_error(JsonLexContext *lex)
{
	if (lex->throw_errors)
		return false;

	lex->error = true;
	return true;
}

/*
 * lex_accept
 *
 * accept the look_ahead token and move the lexer to the next token if the
 * look_ahead token matches the token parameter. In that case, and if required,
 * also hand back the de-escaped lexeme.
 *
 * returns true if the token matched, false otherwise.
 */
static inline bool
lex_accept(JsonLexContext *lex, JsonTokenType token, char **lexeme)
{
	if (lex->token_type == token)
	{
		if (lexeme != NULL)
			*lexeme = lex_peek_value(lex);

		return json_lex(lex);
	}
	return false;
}

/*
 * lex_accept
 *
 * move the lexer to the next token if the current look_ahead token matches
 * the parameter token. Otherwise, report an error.
 */
static inline bool
lex_expect(JsonParseContext ctx, JsonLexContext *lex, JsonTokenType token)
{
	if (lex_accept(lex, token, NULL))
		return true;

	if (!lex_set_error(lex))
		report_parse_error(ctx, lex);

	return false;
}

/* msb for char */
#define HIGHBIT					(0x80)
#define IS_HIGHBIT_SET(ch)		((unsigned char)(ch) & HIGHBIT)

/* chars to consider as part of an alphanumeric token */
#define JSON_ALPHANUMERIC_CHAR(c)  \
	(((c) >= 'a' && (c) <= 'z') || \
	 ((c) >= 'A' && (c) <= 'Z') || \
	 ((c) >= '0' && (c) <= '9') || \
	 (c) == '_' || \
	 IS_HIGHBIT_SET(c))

/*
 * Utility function to check if a string is a valid JSON number.
 *
 * str is of length len, and need not be null-terminated.
 */
bool
IsValidJsonNumber(const char *str, int len)
{
	bool		numeric_error;
	int			total_len;
	JsonLexContext dummy_lex;

	if (len <= 0)
		return false;

	/*
	 * json_lex_number expects a leading  '-' to have been eaten already.
	 *
	 * having to cast away the constness of str is ugly, but there's not much
	 * easy alternative.
	 */
	if (*str == '-')
	{
		dummy_lex.input = unconstify(char *, str) + 1;
		dummy_lex.input_length = len - 1;
	}
	else
	{
		dummy_lex.input = unconstify(char *, str);
		dummy_lex.input_length = len;
	}

	json_lex_number(&dummy_lex, dummy_lex.input, &numeric_error, &total_len);

	return (!numeric_error) && (total_len == dummy_lex.input_length);
}

bool
pg_json_validate(const char *json, bool need_escapes)
{
	JsonLexContext *lex;
	bool		res;

	/* validate it */
	lex = makeJsonLexContext((char *) json, need_escapes);
	lex->throw_errors = false;

	res = pg_parse_json(lex, &nullSemAction);

	if (lex->strval)
	{
		pfree(lex->strval->data);
		pfree(lex->strval);
	}
	pfree(lex);

	return res;
}

/*
 * makeJsonLexContext
 *
 * lex constructor, with or without StringInfo object
 * for de-escaped lexemes.
 *
 * Without is better as it makes the processing faster, so only make one
 * if really required.
 *
 * If you already have the json as a text* value, use the first of these
 * functions, otherwise use  makeJsonLexContextCstringLen().
 */
JsonLexContext *
makeJsonLexContext(char *json, bool need_escapes)
{
	return makeJsonLexContextCstringLen(json, strlen(json), need_escapes);
}

JsonLexContext *
makeJsonLexContextCstringLen(char *json, int len, bool need_escapes)
{
	JsonLexContext *lex = (JsonLexContext *) palloc0(sizeof(JsonLexContext));

	lex->input = lex->token_terminator = lex->line_start = json;
	lex->line_number = 1;
	lex->input_length = len;
	lex->throw_errors = true;
	if (need_escapes)
		lex->strval = makeStringInfo();
	return lex;
}

/*
 * pg_parse_json
 *
 * Publicly visible entry point for the JSON parser.
 *
 * lex is a lexing context, set up for the json to be processed by calling
 * makeJsonLexContext(). sem is a structure of function pointers to semantic
 * action routines to be called at appropriate spots during parsing, and a
 * pointer to a state object to be passed to those routines.
 */
bool
pg_parse_json(JsonLexContext *lex, JsonSemAction *sem)
{
	JsonTokenType tok;

	/* get the initial token */
	if (!json_lex(lex))
		return false;

	tok = lex_peek(lex);

	/* parse by recursive descent */
	switch (tok)
	{
		case JSON_TOKEN_OBJECT_START:
			parse_object(lex, sem);
			break;
		case JSON_TOKEN_ARRAY_START:
			parse_array(lex, sem);
			break;
		default:
			parse_scalar(lex, sem); /* json can be a bare scalar */
	}

	return !lex->error && lex_expect(JSON_PARSE_END, lex, JSON_TOKEN_END);
}

/*
 *	Recursive Descent parse routines. There is one for each structural
 *	element in a json document:
 *	  - scalar (string, number, true, false, null)
 *	  - array  ( [ ] )
 *	  - array element
 *	  - object ( { } )
 *	  - object field
 */
static inline void
parse_scalar(JsonLexContext *lex, JsonSemAction *sem)
{
	char	   *val = NULL;
	json_scalar_action sfunc = sem->scalar;
	char	  **valaddr;
	JsonTokenType tok = lex_peek(lex);

	valaddr = sfunc == NULL ? NULL : &val;

	/* a scalar must be a string, a number, true, false, or null */
	switch (tok)
	{
		case JSON_TOKEN_TRUE:
			lex_accept(lex, JSON_TOKEN_TRUE, valaddr);
			break;
		case JSON_TOKEN_FALSE:
			lex_accept(lex, JSON_TOKEN_FALSE, valaddr);
			break;
		case JSON_TOKEN_NULL:
			lex_accept(lex, JSON_TOKEN_NULL, valaddr);
			break;
		case JSON_TOKEN_NUMBER:
			lex_accept(lex, JSON_TOKEN_NUMBER, valaddr);
			break;
		case JSON_TOKEN_STRING:
			lex_accept(lex, JSON_TOKEN_STRING, valaddr);
			break;
		default:
			if (!lex_set_error(lex))
				report_parse_error(JSON_PARSE_VALUE, lex);
			return;
	}

	if (sfunc != NULL && !lex->error)
		(*sfunc) (sem->semstate, val, tok);
}

static bool
parse_object_field(JsonLexContext *lex, JsonSemAction *sem)
{
	/*
	 * An object field is "fieldname" : value where value can be a scalar,
	 * object or array.  Note: in user-facing docs and error messages, we
	 * generally call a field name a "key".
	 */

	char	   *fname = NULL;	/* keep compiler quiet */
	json_ofield_action ostart = sem->object_field_start;
	json_ofield_action oend = sem->object_field_end;
	bool		isnull;
	char	  **fnameaddr = NULL;
	JsonTokenType tok;

	if (ostart != NULL || oend != NULL)
		fnameaddr = &fname;

	if (!lex_accept(lex, JSON_TOKEN_STRING, fnameaddr))
	{
		if (!lex_set_error(lex))
			report_parse_error(JSON_PARSE_STRING, lex);
		return false;
	}

	if (!lex_expect(JSON_PARSE_OBJECT_LABEL, lex, JSON_TOKEN_COLON))
		return false;

	tok = lex_peek(lex);
	isnull = tok == JSON_TOKEN_NULL;

	if (ostart != NULL)
	{
		(*ostart) (sem->semstate, fname, isnull);

		if (lex->error)
			return false;
	}

	switch (tok)
	{
		case JSON_TOKEN_OBJECT_START:
			parse_object(lex, sem);
			break;
		case JSON_TOKEN_ARRAY_START:
			parse_array(lex, sem);
			break;
		default:
			parse_scalar(lex, sem);
	}

	if (lex->error)
		return false;

	if (oend != NULL)
		(*oend) (sem->semstate, fname, isnull);

	return !lex->error;
}

static void
parse_object(JsonLexContext *lex, JsonSemAction *sem)
{
	/*
	 * an object is a possibly empty sequence of object fields, separated by
	 * commas and surrounded by curly braces.
	 */
	json_struct_action ostart = sem->object_start;
	json_struct_action oend = sem->object_end;
	JsonTokenType tok;

	check_stack_depth();

	if (ostart != NULL)
	{
		(*ostart) (sem->semstate);

		if (lex->error)
			return;
	}

	/*
	 * Data inside an object is at a higher nesting level than the object
	 * itself. Note that we increment this after we call the semantic routine
	 * for the object start and restore it before we call the routine for the
	 * object end.
	 */
	lex->lex_level++;

	/* we know this will succeed, just clearing the token */
	if (!lex_expect(JSON_PARSE_OBJECT_START, lex, JSON_TOKEN_OBJECT_START))
		return;

	tok = lex_peek(lex);
	switch (tok)
	{
		case JSON_TOKEN_STRING:
			if (!parse_object_field(lex, sem))
				return;
			while (lex_accept(lex, JSON_TOKEN_COMMA, NULL))
				if (!parse_object_field(lex, sem))
					return;
			break;
		case JSON_TOKEN_OBJECT_END:
			break;
		default:
			/* case of an invalid initial token inside the object */
			if (!lex_set_error(lex))
				report_parse_error(JSON_PARSE_OBJECT_START, lex);
			return;
	}

	if (!lex_expect(JSON_PARSE_OBJECT_NEXT, lex, JSON_TOKEN_OBJECT_END))
		return;

	lex->lex_level--;

	if (oend != NULL)
		(*oend) (sem->semstate);
}

static bool
parse_array_element(JsonLexContext *lex, JsonSemAction *sem)
{
	json_aelem_action astart = sem->array_element_start;
	json_aelem_action aend = sem->array_element_end;
	JsonTokenType tok = lex_peek(lex);

	bool		isnull;

	isnull = tok == JSON_TOKEN_NULL;

	if (astart != NULL)
	{
		(*astart) (sem->semstate, isnull);

		if (lex->error)
			return false;
	}

	/* an array element is any object, array or scalar */
	switch (tok)
	{
		case JSON_TOKEN_OBJECT_START:
			parse_object(lex, sem);
			break;
		case JSON_TOKEN_ARRAY_START:
			parse_array(lex, sem);
			break;
		default:
			parse_scalar(lex, sem);
	}

	if (lex->error)
		return false;

	if (aend != NULL)
		(*aend) (sem->semstate, isnull);

	return !lex->error;
}

static void
parse_array(JsonLexContext *lex, JsonSemAction *sem)
{
	/*
	 * an array is a possibly empty sequence of array elements, separated by
	 * commas and surrounded by square brackets.
	 */
	json_struct_action astart = sem->array_start;
	json_struct_action aend = sem->array_end;

	check_stack_depth();

	if (astart != NULL)
	{
		(*astart) (sem->semstate);

		if (lex->error)
			return;
	}

	/*
	 * Data inside an array is at a higher nesting level than the array
	 * itself. Note that we increment this after we call the semantic routine
	 * for the array start and restore it before we call the routine for the
	 * array end.
	 */
	lex->lex_level++;

	if (!lex_expect(JSON_PARSE_ARRAY_START, lex, JSON_TOKEN_ARRAY_START))
		return;

	if (lex_peek(lex) != JSON_TOKEN_ARRAY_END)
	{
		if (!parse_array_element(lex, sem))
			return;

		while (lex_accept(lex, JSON_TOKEN_COMMA, NULL))
			if (!parse_array_element(lex, sem))
				return;
	}

	if (!lex_expect(JSON_PARSE_ARRAY_NEXT, lex, JSON_TOKEN_ARRAY_END))
		return;

	lex->lex_level--;

	if (aend != NULL)
		(*aend) (sem->semstate);
}

/*
 * Lex one token from the input stream.
 */
static inline bool
json_lex(JsonLexContext *lex)
{
	char	   *s;
	int			len;

	/* Skip leading whitespace. */
	s = lex->token_terminator;
	len = s - lex->input;
	while (len < lex->input_length &&
		   (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r'))
	{
		if (*s == '\n')
			++lex->line_number;
		++s;
		++len;
	}
	lex->token_start = s;

	/* Determine token type. */
	if (len >= lex->input_length)
	{
		lex->token_start = NULL;
		lex->prev_token_terminator = lex->token_terminator;
		lex->token_terminator = s;
		lex->token_type = JSON_TOKEN_END;
	}
	else
		switch (*s)
		{
				/* Single-character token, some kind of punctuation mark. */
			case '{':
				lex->prev_token_terminator = lex->token_terminator;
				lex->token_terminator = s + 1;
				lex->token_type = JSON_TOKEN_OBJECT_START;
				break;
			case '}':
				lex->prev_token_terminator = lex->token_terminator;
				lex->token_terminator = s + 1;
				lex->token_type = JSON_TOKEN_OBJECT_END;
				break;
			case '[':
				lex->prev_token_terminator = lex->token_terminator;
				lex->token_terminator = s + 1;
				lex->token_type = JSON_TOKEN_ARRAY_START;
				break;
			case ']':
				lex->prev_token_terminator = lex->token_terminator;
				lex->token_terminator = s + 1;
				lex->token_type = JSON_TOKEN_ARRAY_END;
				break;
			case ',':
				lex->prev_token_terminator = lex->token_terminator;
				lex->token_terminator = s + 1;
				lex->token_type = JSON_TOKEN_COMMA;
				break;
			case ':':
				lex->prev_token_terminator = lex->token_terminator;
				lex->token_terminator = s + 1;
				lex->token_type = JSON_TOKEN_COLON;
				break;
			case '"':
				/* string */
				json_lex_string(lex);
				lex->token_type = JSON_TOKEN_STRING;
				break;
			case '-':
				/* Negative number. */
				json_lex_number(lex, s + 1, NULL, NULL);
				lex->token_type = JSON_TOKEN_NUMBER;
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				/* Positive number. */
				json_lex_number(lex, s, NULL, NULL);
				lex->token_type = JSON_TOKEN_NUMBER;
				break;
			default:
				{
					char	   *p;

					/*
					 * We're not dealing with a string, number, legal
					 * punctuation mark, or end of string.  The only legal
					 * tokens we might find here are true, false, and null,
					 * but for error reporting purposes we scan until we see a
					 * non-alphanumeric character.  That way, we can report
					 * the whole word as an unexpected token, rather than just
					 * some unintuitive prefix thereof.
					 */
					for (p = s; p - s < lex->input_length - len && JSON_ALPHANUMERIC_CHAR(*p); p++)
						 /* skip */ ;

					/*
					 * We got some sort of unexpected punctuation or an
					 * otherwise unexpected character, so just complain about
					 * that one character.
					 */
					if (p == s)
					{
						lex->prev_token_terminator = lex->token_terminator;
						lex->token_terminator = s + 1;
						if (!lex_set_error(lex))
							report_invalid_token(lex);
						return false;
					}

					/*
					 * We've got a real alphanumeric token here.  If it
					 * happens to be true, false, or null, all is well.  If
					 * not, error out.
					 */
					lex->prev_token_terminator = lex->token_terminator;
					lex->token_terminator = p;
					if (p - s == 4)
					{
						if (memcmp(s, "true", 4) == 0)
							lex->token_type = JSON_TOKEN_TRUE;
						else if (memcmp(s, "null", 4) == 0)
							lex->token_type = JSON_TOKEN_NULL;
						else if (!lex_set_error(lex))
							report_invalid_token(lex);
					}
					else if (p - s == 5 && memcmp(s, "false", 5) == 0)
						lex->token_type = JSON_TOKEN_FALSE;
					else if (!lex_set_error(lex))
						report_invalid_token(lex);

				}
		}						/* end of switch */

	return !lex->error;
}

/*
 * The next token in the input stream is known to be a string; lex it.
 */
static inline void
json_lex_string(JsonLexContext *lex)
{
	char	   *s;
	int			len;
	int			hi_surrogate = -1;

	if (lex->strval != NULL)
		resetStringInfo(lex->strval);

	Assert(lex->input_length > 0);
	s = lex->token_start;
	len = lex->token_start - lex->input;
	for (;;)
	{
		s++;
		len++;
		/* Premature end of the string. */
		if (len >= lex->input_length)
		{
			lex->token_terminator = s;
			if (!lex_set_error(lex))
				report_invalid_token(lex);
			return;
		}
		else if (*s == '"')
			break;
		else if ((unsigned char) *s < 32)
		{
			/* Per RFC4627, these characters MUST be escaped. */
			/* Since *s isn't printable, exclude it from the context string */
			lex->token_terminator = s;
			if (lex_set_error(lex))
				return;
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					 errmsg("invalid input syntax for type %s", "json"),
					 errdetail("Character with value 0x%02x must be escaped.",
							   (unsigned char) *s),
					 report_json_context(lex)));
		}
		else if (*s == '\\')
		{
			/* OK, we have an escape character. */
			s++;
			len++;
			if (len >= lex->input_length)
			{
				lex->token_terminator = s;
				if (!lex_set_error(lex))
					report_invalid_token(lex);
				return;
			}
			else if (*s == 'u')
			{
				int			i;
				int			ch = 0;

				for (i = 1; i <= 4; i++)
				{
					s++;
					len++;
					if (len >= lex->input_length)
					{
						lex->token_terminator = s;
						if (!lex_set_error(lex))
							report_invalid_token(lex);
						return;
					}
					else if (*s >= '0' && *s <= '9')
						ch = (ch * 16) + (*s - '0');
					else if (*s >= 'a' && *s <= 'f')
						ch = (ch * 16) + (*s - 'a') + 10;
					else if (*s >= 'A' && *s <= 'F')
						ch = (ch * 16) + (*s - 'A') + 10;
					else
					{
						if (lex_set_error(lex))
							return;
						lex->token_terminator = s + pg_mblen(s);
						ereport(ERROR,
								(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
								 errmsg("invalid input syntax for type %s",
										"json"),
								 errdetail("\"\\u\" must be followed by four hexadecimal digits."),
								 report_json_context(lex)));
					}
				}
				if (lex->strval != NULL)
				{
					char		utf8str[5];
					int			utf8len;

					if (ch >= 0xd800 && ch <= 0xdbff)
					{
						if (hi_surrogate != -1)
						{
							if (lex_set_error(lex))
								return;
							ereport(ERROR,
									(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
									 errmsg("invalid input syntax for type %s",
											"json"),
									 errdetail("Unicode high surrogate must not follow a high surrogate."),
									 report_json_context(lex)));
						}
						hi_surrogate = (ch & 0x3ff) << 10;
						continue;
					}
					else if (ch >= 0xdc00 && ch <= 0xdfff)
					{
						if (hi_surrogate == -1)
						{
							if (lex_set_error(lex))
								return;
							ereport(ERROR,
									(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
									 errmsg("invalid input syntax for type %s", "json"),
									 errdetail("Unicode low surrogate must follow a high surrogate."),
									 report_json_context(lex)));
						}
						ch = 0x10000 + hi_surrogate + (ch & 0x3ff);
						hi_surrogate = -1;
					}

					if (hi_surrogate != -1)
					{
						if (lex_set_error(lex))
							return;
						ereport(ERROR,
								(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
								 errmsg("invalid input syntax for type %s", "json"),
								 errdetail("Unicode low surrogate must follow a high surrogate."),
								 report_json_context(lex)));
					}

					/*
					 * For UTF8, replace the escape sequence by the actual
					 * utf8 character in lex->strval. Do this also for other
					 * encodings if the escape designates an ASCII character,
					 * otherwise raise an error.
					 */

					if (ch == 0)
					{
						/* We can't allow this, since our TEXT type doesn't */
						if (lex_set_error(lex))
							return;
						ereport(ERROR,
								(errcode(ERRCODE_UNTRANSLATABLE_CHARACTER),
								 errmsg("unsupported Unicode escape sequence"),
								 errdetail("\\u0000 cannot be converted to text."),
								 report_json_context(lex)));
					}
					else if (GetDatabaseEncoding() == PG_UTF8)
					{
						unicode_to_utf8(ch, (unsigned char *) utf8str);
						utf8len = pg_utf_mblen((unsigned char *) utf8str);
						appendBinaryStringInfo(lex->strval, utf8str, utf8len);
					}
					else if (ch <= 0x007f)
					{
						/*
						 * This is the only way to designate things like a
						 * form feed character in JSON, so it's useful in all
						 * encodings.
						 */
						appendStringInfoChar(lex->strval, (char) ch);
					}
					else
					{
						if (lex_set_error(lex))
							return;
						ereport(ERROR,
								(errcode(ERRCODE_UNTRANSLATABLE_CHARACTER),
								 errmsg("unsupported Unicode escape sequence"),
								 errdetail("Unicode escape values cannot be used for code point values above 007F when the server encoding is not UTF8."),
								 report_json_context(lex)));
					}

				}
			}
			else if (lex->strval != NULL)
			{
				if (hi_surrogate != -1)
				{
					if (lex_set_error(lex))
						return;
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
							 errmsg("invalid input syntax for type %s",
									"json"),
							 errdetail("Unicode low surrogate must follow a high surrogate."),
							 report_json_context(lex)));
				}

				switch (*s)
				{
					case '"':
					case '\\':
					case '/':
						appendStringInfoChar(lex->strval, *s);
						break;
					case 'b':
						appendStringInfoChar(lex->strval, '\b');
						break;
					case 'f':
						appendStringInfoChar(lex->strval, '\f');
						break;
					case 'n':
						appendStringInfoChar(lex->strval, '\n');
						break;
					case 'r':
						appendStringInfoChar(lex->strval, '\r');
						break;
					case 't':
						appendStringInfoChar(lex->strval, '\t');
						break;
					default:
						/* Not a valid string escape, so error out. */
						if (lex_set_error(lex))
							return;
						lex->token_terminator = s + pg_mblen(s);
						ereport(ERROR,
								(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
								 errmsg("invalid input syntax for type %s",
										"json"),
								 errdetail("Escape sequence \"\\%s\" is invalid.",
										   extract_mb_char(s)),
								 report_json_context(lex)));
				}
			}
			else if (strchr("\"\\/bfnrt", *s) == NULL)
			{
				/*
				 * Simpler processing if we're not bothered about de-escaping
				 *
				 * It's very tempting to remove the strchr() call here and
				 * replace it with a switch statement, but testing so far has
				 * shown it's not a performance win.
				 */
				if (lex_set_error(lex))
					return;
				lex->token_terminator = s + pg_mblen(s);
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Escape sequence \"\\%s\" is invalid.",
								   extract_mb_char(s)),
						 report_json_context(lex)));
			}

		}
		else if (lex->strval != NULL)
		{
			if (hi_surrogate != -1)
			{
				if (lex_set_error(lex))
					return;
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Unicode low surrogate must follow a high surrogate."),
						 report_json_context(lex)));
			}

			appendStringInfoChar(lex->strval, *s);
		}

	}

	if (hi_surrogate != -1)
	{
		if (lex_set_error(lex))
			return;
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid input syntax for type %s", "json"),
				 errdetail("Unicode low surrogate must follow a high surrogate."),
				 report_json_context(lex)));
	}

	/* Hooray, we found the end of the string! */
	lex->prev_token_terminator = lex->token_terminator;
	lex->token_terminator = s + 1;
}

/*
 * The next token in the input stream is known to be a number; lex it.
 *
 * In JSON, a number consists of four parts:
 *
 * (1) An optional minus sign ('-').
 *
 * (2) Either a single '0', or a string of one or more digits that does not
 *	   begin with a '0'.
 *
 * (3) An optional decimal part, consisting of a period ('.') followed by
 *	   one or more digits.  (Note: While this part can be omitted
 *	   completely, it's not OK to have only the decimal point without
 *	   any digits afterwards.)
 *
 * (4) An optional exponent part, consisting of 'e' or 'E', optionally
 *	   followed by '+' or '-', followed by one or more digits.  (Note:
 *	   As with the decimal part, if 'e' or 'E' is present, it must be
 *	   followed by at least one digit.)
 *
 * The 's' argument to this function points to the ostensible beginning
 * of part 2 - i.e. the character after any optional minus sign, or the
 * first character of the string if there is none.
 *
 * If num_err is not NULL, we return an error flag to *num_err rather than
 * raising an error for a badly-formed number.  Also, if total_len is not NULL
 * the distance from lex->input to the token end+1 is returned to *total_len.
 */
static inline void
json_lex_number(JsonLexContext *lex, char *s,
				bool *num_err, int *total_len)
{
	bool		error = false;
	int			len = s - lex->input;

	/* Part (1): leading sign indicator. */
	/* Caller already did this for us; so do nothing. */

	/* Part (2): parse main digit string. */
	if (len < lex->input_length && *s == '0')
	{
		s++;
		len++;
	}
	else if (len < lex->input_length && *s >= '1' && *s <= '9')
	{
		do
		{
			s++;
			len++;
		} while (len < lex->input_length && *s >= '0' && *s <= '9');
	}
	else
		error = true;

	/* Part (3): parse optional decimal portion. */
	if (len < lex->input_length && *s == '.')
	{
		s++;
		len++;
		if (len == lex->input_length || *s < '0' || *s > '9')
			error = true;
		else
		{
			do
			{
				s++;
				len++;
			} while (len < lex->input_length && *s >= '0' && *s <= '9');
		}
	}

	/* Part (4): parse optional exponent. */
	if (len < lex->input_length && (*s == 'e' || *s == 'E'))
	{
		s++;
		len++;
		if (len < lex->input_length && (*s == '+' || *s == '-'))
		{
			s++;
			len++;
		}
		if (len == lex->input_length || *s < '0' || *s > '9')
			error = true;
		else
		{
			do
			{
				s++;
				len++;
			} while (len < lex->input_length && *s >= '0' && *s <= '9');
		}
	}

	/*
	 * Check for trailing garbage.  As in json_lex(), any alphanumeric stuff
	 * here should be considered part of the token for error-reporting
	 * purposes.
	 */
	for (; len < lex->input_length && JSON_ALPHANUMERIC_CHAR(*s); s++, len++)
		error = true;

	if (total_len != NULL)
		*total_len = len;

	if (num_err != NULL)
	{
		/* let the caller handle any error */
		*num_err = error;
	}
	else
	{
		/* return token endpoint */
		lex->prev_token_terminator = lex->token_terminator;
		lex->token_terminator = s;
		/* handle error if any */
		if (error && !lex_set_error(lex))
			report_invalid_token(lex);
	}
}

/*
 * Report a parse error.
 *
 * lex->token_start and lex->token_terminator must identify the current token.
 */
static void
report_parse_error(JsonParseContext ctx, JsonLexContext *lex)
{
	char	   *token;
	int			toklen;

	/* Handle case where the input ended prematurely. */
	if (lex->token_start == NULL || lex->token_type == JSON_TOKEN_END)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid input syntax for type %s", "json"),
				 errdetail("The input string ended unexpectedly."),
				 report_json_context(lex)));

	/* Separate out the current token. */
	toklen = lex->token_terminator - lex->token_start;
	token = (char *) palloc(toklen + 1);
	memcpy(token, lex->token_start, toklen);
	token[toklen] = '\0';

	/* Complain, with the appropriate detail message. */
	if (ctx == JSON_PARSE_END)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
				 errmsg("invalid input syntax for type %s", "json"),
				 errdetail("Expected end of input, but found \"%s\".",
						   token),
				 report_json_context(lex)));
	else
	{
		switch (ctx)
		{
			case JSON_PARSE_VALUE:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Expected JSON value, but found \"%s\".",
								   token),
						 report_json_context(lex)));
				break;
			case JSON_PARSE_STRING:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Expected string, but found \"%s\".",
								   token),
						 report_json_context(lex)));
				break;
			case JSON_PARSE_ARRAY_START:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Expected array element or \"]\", but found \"%s\".",
								   token),
						 report_json_context(lex)));
				break;
			case JSON_PARSE_ARRAY_NEXT:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Expected \",\" or \"]\", but found \"%s\".",
								   token),
						 report_json_context(lex)));
				break;
			case JSON_PARSE_OBJECT_START:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Expected string or \"}\", but found \"%s\".",
								   token),
						 report_json_context(lex)));
				break;
			case JSON_PARSE_OBJECT_LABEL:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Expected \":\", but found \"%s\".",
								   token),
						 report_json_context(lex)));
				break;
			case JSON_PARSE_OBJECT_NEXT:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Expected \",\" or \"}\", but found \"%s\".",
								   token),
						 report_json_context(lex)));
				break;
			case JSON_PARSE_OBJECT_COMMA:
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
						 errmsg("invalid input syntax for type %s", "json"),
						 errdetail("Expected string, but found \"%s\".",
								   token),
						 report_json_context(lex)));
				break;
			default:
				elog(ERROR, "unexpected json parse state: %d", ctx);
		}
	}
}

/*
 * Report an invalid input token.
 *
 * lex->token_start and lex->token_terminator must identify the token.
 */
static void
report_invalid_token(JsonLexContext *lex)
{
	char	   *token;
	int			toklen;

	/* Separate out the offending token. */
	toklen = lex->token_terminator - lex->token_start;
	token = (char *) palloc(toklen + 1);
	memcpy(token, lex->token_start, toklen);
	token[toklen] = '\0';

	ereport(ERROR,
			(errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
			 errmsg("invalid input syntax for type %s", "json"),
			 errdetail("Token \"%s\" is invalid.", token),
			 report_json_context(lex)));
}

/*
 * Report a CONTEXT line for bogus JSON input.
 *
 * lex->token_terminator must be set to identify the spot where we detected
 * the error.  Note that lex->token_start might be NULL, in case we recognized
 * error at EOF.
 *
 * The return value isn't meaningful, but we make it non-void so that this
 * can be invoked inside ereport().
 */
static char *
report_json_context(JsonLexContext *lex)
{
	const char *context_start;
	const char *context_end;
	const char *line_start;
	int			line_number;
	char	   *ctxt;
	int			ctxtlen;
	const char *prefix;
	const char *suffix;

	/* Choose boundaries for the part of the input we will display */
	context_start = lex->input;
	context_end = lex->token_terminator;
	line_start = context_start;
	line_number = 1;
	for (;;)
	{
		/* Always advance over newlines */
		if (context_start < context_end && *context_start == '\n')
		{
			context_start++;
			line_start = context_start;
			line_number++;
			continue;
		}
		/* Otherwise, done as soon as we are close enough to context_end */
		if (context_end - context_start < 50)
			break;
		/* Advance to next multibyte character */
		if (IS_HIGHBIT_SET(*context_start))
			context_start += pg_mblen(context_start);
		else
			context_start++;
	}

	/*
	 * We add "..." to indicate that the excerpt doesn't start at the
	 * beginning of the line ... but if we're within 3 characters of the
	 * beginning of the line, we might as well just show the whole line.
	 */
	if (context_start - line_start <= 3)
		context_start = line_start;

	/* Get a null-terminated copy of the data to present */
	ctxtlen = context_end - context_start;
	ctxt = (char *) palloc(ctxtlen + 1);
	memcpy(ctxt, context_start, ctxtlen);
	ctxt[ctxtlen] = '\0';

	/*
	 * Show the context, prefixing "..." if not starting at start of line, and
	 * suffixing "..." if not ending at end of line.
	 */
	prefix = (context_start > line_start) ? "..." : "";
	suffix = (lex->token_type != JSON_TOKEN_END && context_end - lex->input < lex->input_length && *context_end != '\n' && *context_end != '\r') ? "..." : "";

	{
		StringInfoData str;
		initStringInfo(&str);
		appendStringInfo(&str, "JSON data, line %d: %s%s%s",
						 line_number, prefix, ctxt, suffix);
		return str.data;
	}
}

/*
 * Extract a single, possibly multi-byte char from the input string.
 */
static char *
extract_mb_char(char *s)
{
	char	   *res;
	int			len;

	len = pg_mblen(s);
	res = (char *) palloc(len + 1);
	memcpy(res, s, len);
	res[len] = '\0';

	return res;
}

/*
 * Produce a JSON string literal, properly escaping characters in the text.
 */
void
escape_json(StringInfo buf, const char *str)
{
	const char *p;

	appendStringInfoCharMacro(buf, '"');
	for (p = str; *p; p++)
	{
		switch (*p)
		{
			case '\b':
				appendStringInfoString(buf, "\\b");
				break;
			case '\f':
				appendStringInfoString(buf, "\\f");
				break;
			case '\n':
				appendStringInfoString(buf, "\\n");
				break;
			case '\r':
				appendStringInfoString(buf, "\\r");
				break;
			case '\t':
				appendStringInfoString(buf, "\\t");
				break;
			case '"':
				appendStringInfoString(buf, "\\\"");
				break;
			case '\\':
				appendStringInfoString(buf, "\\\\");
				break;
			default:
				if ((unsigned char) *p < ' ')
					appendStringInfo(buf, "\\u%04x", (int) *p);
				else
					appendStringInfoCharMacro(buf, *p);
				break;
		}
	}
	appendStringInfoCharMacro(buf, '"');
}
