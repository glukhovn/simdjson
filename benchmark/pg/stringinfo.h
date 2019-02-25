#ifndef __STRINGINFO_H__
#define __STRINGINFO_H__
#include "postgres.h"

typedef struct StringInfoData
{
	char	   *data;
	int			len;
	int			maxlen;
	int			cursor;
} StringInfoData;

typedef StringInfoData *StringInfo;

/*------------------------
 * appendStringInfoCharMacro
 * As above, but a macro for even more speed where it matters.
 * Caution: str argument will be evaluated multiple times.
 */
#define appendStringInfoCharMacro(str,ch) \
	(((str)->len + 1 >= (str)->maxlen) ? \
	 appendStringInfoChar(str, ch) : \
	 (void)((str)->data[(str)->len] = (ch), (str)->data[++(str)->len] = '\0'))

extern void resetStringInfo(StringInfo str);
extern void initStringInfo(StringInfo str);
extern StringInfo makeStringInfo(void);
extern void enlargeStringInfo(StringInfo str, int needed);
extern int appendStringInfoVA(StringInfo str, const char *fmt, va_list args);
extern void appendStringInfo(StringInfo str, const char *fmt,...);
extern void appendBinaryStringInfo(StringInfo str, const char *data, int datalen);
extern void appendStringInfoString(StringInfo str, const char *s);
extern void appendStringInfoChar(StringInfo str, char ch);
extern void appendStringInfoSpaces(StringInfo str, int count);
extern void appendBinaryStringInfoNT(StringInfo str, const char *data, int datalen);

#endif /* __STRINGINFO_H__ */
