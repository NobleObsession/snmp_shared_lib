#ifndef SNMP_PDU_H
#define SNMP_PDU_H

#include <cstddef>

#include "shared_constants.h"

#define MAX_OID_LEN	    128 /* max subid's in an oid */

typedef unsigned long oid;
#define MAX_SUBID   0xFFFFFFFFUL
#define NETSNMP_PRIo "l"

typedef union {
   long           *integer;
   u_char         *string;
   oid            *objid;
   u_char         *bitstring;
   struct counter64 *counter64;
} netsnmp_vardata;

/** @typedef struct variable_list netsnmp_variable_list
 * Typedefs the variable_list struct into netsnmp_variable_list */
/** @struct variable_list
 * The netsnmp variable list binding structure, it's typedef'd to
 * netsnmp_variable_list.
 */
typedef struct variable_list {
   /** NULL for last variable */
   struct variable_list *next_variable;
   /** Object identifier of variable */
   oid            *name;
   /** number of subid's in name */
   size_t          name_length;
   /** ASN type of variable */
   u_char          type;
   /** value of variable */
    netsnmp_vardata val;
   /** the length of the value to be copied into buf */
   size_t          val_len;
   /** buffer to hold the OID */
   oid             name_loc[MAX_OID_LEN];
   /** 90 percentile < 40. */
   u_char          buf[40];
   /** (Opaque) hook for additional data */
   void           *data;
   /** callback to free above */
   void            (*dataFreeHook)(void *);
   int             index;
} netsnmp_variable_list;

/** @struct snmp_pdu
 * The snmp protocol data unit.
 */
struct snmp_pdu {
    /** snmp version */
    long            version;
    netsnmp_variable_list *variables;
    /** Request id - note: incremented for each retry */
        long            reqid;

    /** Error status (non_repeaters in GetBulk) */
        long            errstat;
    /** Error index (max_repetitions in GetBulk) */
        long            errindex;
};

#endif // SNMP_PDU_H
