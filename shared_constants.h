#ifndef SHARED_CONSTANTS_H
#define SHARED_CONSTANTS_H

#include <stdlib.h>

#define u_char unsigned char

#define NETSNMP_BIGENDIAN 0

/** @def SNMP_FREE(s)
    Frees a pointer only if it is !NULL and sets its value to NULL */
#define SNMP_FREE(s)    do { if (s) { free((void *)s); s=NULL; } } while(0)

#define SNMPERR_GENERR			(-1)

/** @def SNMP_MIN(a, b)
    Computers the minimum of a and b. */
#define SNMP_MIN(a,b) ((a) > (b) ? (b) : (a))

/** @def SNMP_MALLOC_TYPEDEF(t)
    Mallocs memory of sizeof(t), zeros it and returns a pointer to it. */
#define SNMP_MALLOC_TYPEDEF(td)  (td *) calloc(1, sizeof(td))

#define snmp_cstrcat(b,l,o,a,s) snmp_strcat(b,l,o,a,(const u_char *)s)

#define FALSE 0
#define TRUE  1

#define SNMP_NOSUCHOBJECT    (ASN_CONTEXT | ASN_PRIMITIVE | 0x0) /* 80=128 */
#define SNMP_NOSUCHINSTANCE  (ASN_CONTEXT | ASN_PRIMITIVE | 0x1) /* 81=129 */
#define SNMP_ENDOFMIBVIEW    (ASN_CONTEXT | ASN_PRIMITIVE | 0x2) /* 82=130 */

#define ASN_SEQUENCE	    0x10U
#define ASN_CONSTRUCTOR	    0x20U
#define ASN_EXTENSION_ID    0x1FU
#define ASN_LONG_LEN	    0x80U
#define ASN_INTEGER         0x02U
#define ASN_OCTET_STR	    0x04U
#define ASN_APPLICATION     0x40U
#define ASN_IPADDRESS   (ASN_APPLICATION | 0)
#define ASN_OBJECT_ID	    0x06U
#define ASN_UNIVERSAL	    0x00U
#define ASN_PRIMITIVE	    0x00U
#define ASN_COUNTER64   (ASN_APPLICATION | 6)
#define ASN_BIT8	    0x80U
#define ASN_NULL	    0x05U
#define ASN_BIT_STR	    0x03U
#define ASN_CONTEXT	    0x80U

#define ASN_COUNTER	(ASN_APPLICATION | 1)
#define ASN_GAUGE	(ASN_APPLICATION | 2)
#define ASN_TIMETICKS   (ASN_APPLICATION | 3)

#endif // SHARED_CONSTANTS_H
