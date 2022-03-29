#ifndef PARSE_PACKET_H
#define PARSE_PACKET_H

#include <sys/types.h>

#include "shared_constants.h"
#include "snmp_pdu.h"


#define SNMP_VERSION_1	   0
#define SNMP_VERSION_2c    1
#define SNMP_VERSION_3     3
#define COMMUNITY_MAX_LEN	256
#define SNMP_MAX_PACKET_LEN (0x7fffffff)

/*
* Error return values.
*/
#define SNMPERR_BAD_VERSION		(-14)



#define IS_EXTENSION_ID(byte)	(((byte) & ASN_EXTENSION_ID) == ASN_EXTENSION_ID)

#define SNMP_MSG_TRAP2      (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x7) /* a7=167 */

#define OID_LENGTH(x)  (sizeof(x) / sizeof((x)[0]))

struct counter64 {
       u_long          high;
       u_long          low;
   };

/**
 * asn_parse_length - interprets the length of the current object.
 *
 *  On exit, length contains the value of this length field.
 *
 *  Returns a pointer to the first byte after this length
 *  field (aka: the start of the data field).
 *  Returns NULL on any error.
 *
 * @param data         IN - pointer to start of length field
 * @param length       OUT - value of length field
 *
 *  @return Returns a pointer to the first byte after this length
 *          field (aka: the start of the data field).
 *          Returns NULL on any error.
 *
 * WARNING: this function does not know the length of the data
*           buffer, so it can go past the end of a short buffer.
 */
u_char         *
asn_parse_length(u_char * data, u_long * length);

/**
 * checks a buffer with a length + data to see if it is big enough for
 *    the length encoding and the data of the parsed length.
 *
 * @param IN  pkt      The buffer
 * @param IN  pkt_len  The length of the bugger
 * @param OUT data_len Pointer to size of data
 *
 * @return Pointer to start of data or NULL if pkt isn't long enough
 *
 * pkt = get_buf(..., &pkt_len);
 * data = asn_parse_nlength(pkt, pkt_len, &data_len);
 * if (NULL == data) { handle_error(); }
 *
 */
u_char *
asn_parse_nlength(u_char *pkt, size_t pkt_len, u_long *data_len);

/**
 * asn_parse_int - pulls a long out of an int type.
 *
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 *
 * @param data       IN - pointer to start of object
 * @param datalength IN/OUT - number of valid bytes left in buffer
 * @param type       OUT - asn type of object
 * @param intp       IN/OUT - pointer to start of output buffer
 * @param intsize    IN - size of output buffer
 *
 * @return pointer to the first byte past the end
 *   of this object (i.e. the start of the next object) Returns NULL on any error
 */
u_char         *
asn_parse_int(u_char * data,
              size_t * datalength,
              u_char * type, long *intp, size_t intsize);

/**
 * asn_parse_header - interprets the ID and length of the current object.
 *
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 *
 *
 * @param data         IN - pointer to start of object
 * @param datalength   IN/OUT - number of valid bytes left in buffer
 * @param type         OUT - asn type of object
 * @return  Returns a pointer to the first byte of the contents of this object.
 *          Returns NULL on any error.
 *
 */
u_char*
asn_parse_header(u_char* data, size_t* datalength, u_char* type);

/**
 * same as asn_parse_header with test for expected type
 *
 * @see asn_parse_header
 *
 * @param data          IN - pointer to start of object
 * @param datalength    IN/OUT - number of valid bytes left in buffer
 * @param type          OUT - asn type of object
 * @param expected_type IN expected type
 * @return  Returns a pointer to the first byte of the contents of this object.
 *          Returns NULL on any error.
 *
 */
u_char*
asn_parse_sequence(u_char * data, size_t * datalength, u_char* type, u_char expected_type,     /* must be this type */
                   const char *estr);

/**
 * asn_parse_string - pulls an octet string out of an ASN octet string type.
 *
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the octet string.
 * ASN.1 octet string   ::=      primstring | cmpdstring
 * primstring           ::= 0x04 asnlength byte {byte}*
 * cmpdstring           ::= 0x24 asnlength string {string}*
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 *
 * @param data        IN - pointer to start of object
 * @param datalength  IN/OUT - number of valid bytes left in buffer
 * @param type        OUT - asn type of object
 * @param string      IN/OUT - pointer to start of output buffer
 * @param strlength   IN/OUT - size of output buffer
 *
 * @return  Returns a pointer to the first byte past the end
 *          of this object (i.e. the start of the next object).
 *          Returns NULL on any error.
 */

u_char         *
asn_parse_string(u_char * data,
                 size_t * datalength,
                 u_char * type, u_char * str, size_t * strlength);

/**
 * snmp_comstr_parse
 *
 * Parameters:
 *	*data		(I)   Message.
 *	*length		(I/O) Bytes left in message.
 *	*community		(O)   Community string.
 *	*community_len		(O)   Length of community string.
 *	*version	(O)   Message version.
 *
 * Returns:
 *	Pointer to the remainder of data.
 *
 *
 * Parse the header of a community string-based message such as that found
 * in SNMPv1 and SNMPv2c.
 */
u_char         *
snmp_comstr_parse(u_char * data,
                  size_t * length,
                  u_char * community, size_t * community_len, long *version);

/**
 * @internal
 * asn_parse_objid - pulls an object indentifier out of an ASN object identifier type.
 *
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "objid" is filled with the object identifier.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 *
 * @param data         IN - pointer to start of object
 * @param datalength   IN/OUT - number of valid bytes left in buffer
 * @param type         OUT - asn type of object
 * @param objid        IN/OUT - pointer to start of output buffer
 * @param objidlength  IN/OUT - number of sub-id's in objid
 *
 *  @return Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 *
 */
u_char         *
asn_parse_objid(u_char * data,
                size_t * datalength,
                u_char * type, oid * objid, size_t * objidlength);

/*
 * u_char * snmp_parse_var_op(
 * u_char *data              IN - pointer to the start of object
 * oid *var_name             OUT - object id of variable
 * int *var_name_len         IN/OUT - length of variable name
 * u_char *var_val_type      OUT - type of variable (int or octet string) (one byte)
 * int *var_val_len          OUT - length of variable
 * u_char **var_val          OUT - pointer to ASN1 encoded value of variable
 * int *listlength          IN/OUT - number of valid bytes left in var_op_list
 */

u_char         *
snmp_parse_var_op(u_char * data,
                  oid * var_name,
                  size_t * var_name_len,
                  u_char * var_val_type,
                  size_t * var_val_len,
                  u_char ** var_val, size_t * listlength);

/*
 * Add object identifier name to SNMP variable.
 * If the name is large, additional memory is allocated.
 * Returns 0 if successful.
 */

int
snmp_set_var_objid(netsnmp_variable_list * vp,
                   const oid * objid, size_t name_length);

/**
 * asn_parse_unsigned_int64 - pulls a 64 bit unsigned long out of an ASN int
 * type.
 *
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 *
 * @param data         IN - pointer to start of object
 * @param datalength   IN/OUT - number of valid bytes left in buffer
 * @param type         OUT - asn type of object
 * @param cp           IN/OUT - pointer to counter struct
 * @param countersize  IN - size of output buffer
 * @return  Returns a pointer to the first byte past the end
 *          of this object (i.e. the start of the next object).
 *          Returns NULL on any error.
 */
u_char* asn_parse_unsigned_int64(u_char * data,
                         size_t * datalength,
                         u_char * type,
                         struct counter64 *cp, size_t countersize);


/**
 * asn_parse_bitstring - pulls a bitstring out of an ASN bitstring type.
 *
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the bit string.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 *
 * @param data         IN - pointer to start of object
 * @param datalength   IN/OUT - number of valid bytes left in buffer
 * @param type         OUT - asn type of object
 * @param string       IN/OUT - pointer to start of output buffer
 * @param strlength    IN/OUT - size of output buffer
 * @return Returns a pointer to the first byte past the end
 *         of this object (i.e. the start of the next object).
 *         Returns NULL on any error.
 */
u_char         *
asn_parse_bitstring(u_char * data,
                    size_t * datalength,
                    u_char * type, u_char * str, size_t * strlength);


/**
* get the fields in the PDU preceding the variable-bindings sequence
*/
u_char* get_preceding_fields(u_char* data, size_t* length, u_char* type, snmp_pdu* pdu);

void get_var_bind_sequences(u_char* data, size_t* length, snmp_pdu* pdu);

void get_pdu(u_char* data, size_t* length,  snmp_pdu* pdu);

#endif // PARSE_PACKET_H

