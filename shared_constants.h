#ifndef SHARED_CONSTANTS_H
#define SHARED_CONSTANTS_H

#include <stdlib.h>

#define u_char unsigned char

#define NETSNMP_BIGENDIAN 0

/** @def SNMP_MIN(a, b)
    Computers the minimum of a and b. */
#define SNMP_MIN(a,b) ((a) > (b) ? (b) : (a))

/** @def SNMP_MALLOC_TYPEDEF(t)
    Mallocs memory of sizeof(t), zeros it and returns a pointer to it. */
#define SNMP_MALLOC_TYPEDEF(td)  (td *) calloc(1, sizeof(td))

#endif // SHARED_CONSTANTS_H
