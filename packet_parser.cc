#include "packet_parser.h"
#include <iostream>
#include <cstring>

u_char*
asn_parse_length(u_char * data, u_long * length){
    static const char *errpre = "parse length";
    char            ebuf[128];
    u_char lengthbyte;

    if (!data || !length) {
        //ERROR_MSG("parse length: NULL pointer");
        return NULL;
    }
    lengthbyte = *data;

    if (lengthbyte & ASN_LONG_LEN) {
        lengthbyte &= ~ASN_LONG_LEN;    /* turn MSb off */
        if (lengthbyte == 0) {
            snprintf(ebuf, sizeof(ebuf),
                     "%s: indefinite length not supported", errpre);
            ebuf[ sizeof(ebuf)-1 ] = 0;
            //ERROR_MSG(ebuf);
            return NULL;
        }
        if (lengthbyte > sizeof(long)) {
            snprintf(ebuf, sizeof(ebuf),
                    "%s: data length %d > %lu not supported", errpre,
                    lengthbyte, (unsigned long)sizeof(long));
            ebuf[ sizeof(ebuf)-1 ] = 0;
           // ERROR_MSG(ebuf);
            return NULL;
        }
        data++;
        *length = 0;            /* protect against short lengths */
        while (lengthbyte--) {
            *length <<= 8;
            *length |= *data++;
        }
        if ((long) *length < 0) {
            snprintf(ebuf, sizeof(ebuf),
                     "%s: negative data length %ld\n", errpre,
                     (long) *length);
            ebuf[ sizeof(ebuf)-1 ] = 0;
           // ERROR_MSG(ebuf);
            return NULL;
        }
        return data;
    } else {                    /* short asnlength */
        *length = (long) lengthbyte;
        return data + 1;
    }
}

u_char *
asn_parse_nlength(u_char *pkt, size_t pkt_len, u_long *data_len)
{
    int len_len;

    if (pkt_len < 1)
        return NULL;               /* always too short */

    if (NULL == pkt || NULL == data_len || NULL == data_len)
        return NULL;

    *data_len = 0;

    if (*pkt & 0x80) {
        /*
         * long length; first byte is length of length (after masking high bit)
         */
        len_len = (int) ((*pkt & ~0x80) + 1);
        /*if (pkt_len < len_len)
            return NULL;     */      /* still too short for length and data */

        /* now we know we have enough data to parse length */
        if (NULL == asn_parse_length(pkt, data_len))
            return NULL;           /* propagate error from asn_parse_length */
    } else {
        /*
         * short length; first byte is the length
         */
        len_len = 1;
        *data_len = *pkt;
    }

    if ((*data_len + len_len) > pkt_len)
        return NULL;

    return (pkt + len_len);
}

u_char*
asn_parse_int(u_char * data,
              size_t * datalength,
              u_char * type, long *intp, size_t intsize){
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    //static const char *errpre = "parse int";
    u_char *bufp = data;
    u_long          asn_length;
    int             i;
    union {
        long          l;
        unsigned char b[sizeof(long)];
    } value;

    if (NULL == data || NULL == datalength || NULL == type || NULL == intp) {
        //ERROR_MSG("parse int: NULL pointer");
        return NULL;
    }

    if (intsize != sizeof(long)) {
        //_asn_size_err(errpre, intsize, sizeof(long));
        return NULL;
    }

    /** need at least 2 bytes to work with: type, length (which might be 0)  */
    if (*datalength < 2) {
        //_asn_short_err(errpre, *datalength, 2);
        return NULL;
    }

    *type = *bufp++;
    if (*type != ASN_INTEGER) {
        //_asn_type_err(errpre, *type);
        return NULL;
    }

    bufp = asn_parse_nlength(bufp, *datalength - 1, &asn_length);
    if (NULL == bufp) {
        //_asn_short_err(errpre, *datalength - 1, asn_length);
        return NULL;
    }

    if ((size_t) asn_length > intsize || (int) asn_length == 0) {
        //_asn_length_err(errpre, (size_t) asn_length, intsize);
        return NULL;
    }

    *datalength -= (int) asn_length + (bufp - data);

   // DEBUGDUMPSETUP("recv", data, bufp - data + asn_length);

    memset(&value.b, *bufp & 0x80 ? 0xff : 0, sizeof(value.b));
    if (NETSNMP_BIGENDIAN) {
        for (i = sizeof(long) - asn_length; asn_length--; i++)
            value.b[i] = *bufp++;
    } else {
        for (i = asn_length - 1; asn_length--; i--)
            value.b[i] = *bufp++;
    }

   // CHECK_OVERFLOW_S(value.l, 1);
    *intp = value.l;
    return bufp;
}

u_char*
asn_parse_header(u_char* data, size_t* datalength, u_char* type)
{
    u_char *bufp;
    u_long          asn_length = 0;
    //const char      *errpre = "parse header";

    if (!data || !datalength || !type) {
        std::cout << "parse header: NULL pointer" << std::endl;
        return NULL;
    }

    /** need at least 2 bytes to work with: type, length (which might be 0) */
    if (*datalength < 2) {
        std::cout << "_asn_short_err(errpre, *datalength, 2" << std::endl;
        return NULL;
    }

    bufp = data;
    /*
     * this only works on data types < 30, i.e. no extension octets
     */
    if (IS_EXTENSION_ID(*bufp)) {
        std::cout << "can't process ID >= 30" << std::endl;
        return NULL;
    }
    *type = *bufp++;

    bufp = asn_parse_nlength(bufp, *datalength - 1, &asn_length);
    if (NULL == bufp) {
        std::cout << "_asn_short_err(errpre, *datalength - 1, asn_length)" << std::endl;
        return NULL;
    }

    *datalength = (int) asn_length;
    return bufp;
}

u_char*
asn_parse_sequence(u_char * data, size_t * datalength, u_char* type, u_char expected_type,     /* must be this type */
                   const char *estr)
{                               /* error message prefix */
    data = asn_parse_header(data, datalength, type);
    if (data && (*type != expected_type)) {
        std::cout << "Unexpected type" << std::endl;
        char            ebuf[128];
        snprintf(ebuf, sizeof(ebuf),
                 "%s header type %02X: s/b %02X", estr,
                (u_char) * type, (u_char) expected_type);
        ebuf[ sizeof(ebuf)-1 ] = 0;
        //ERROR_MSG(ebuf);
        return NULL;
    }
    return data;
}

u_char         *
asn_parse_string(u_char * data,
                 size_t * datalength,
                 u_char * type, u_char * str, size_t * strlength)
{
    u_char         *bufp = data;
    u_long          asn_length;

    if (NULL == data || NULL == datalength || NULL == type || NULL == str ||
        NULL == strlength) {
        std::cout << "parse string: NULL pointer" << std::endl;
        return NULL;
    }

    /** need at least 2 bytes to work with: type, length (which might be 0)  */
    if (*datalength < 2) {
        std::cout << "parse string: datalength < 2" << std::endl;
        return NULL;
    }

    *type = *bufp++;
    if (*type != ASN_OCTET_STR && *type != ASN_IPADDRESS) {
        std::cout << "parse string: error type" << std::endl;
        return NULL;
    }

    bufp = asn_parse_nlength(bufp, *datalength - 1, &asn_length);
    if (NULL == bufp) {
        std::cout << "parse string: asn_parse_nlength" << std::endl;
        return NULL;
    }

    if (asn_length > *strlength) {
        std::cout << "parse string: asn_length > *strlength" << std::endl;
        return NULL;
    }

    memmove(str, bufp, asn_length);
    if (*strlength > asn_length)
        str[asn_length] = 0;
    *strlength = asn_length;
    *datalength -= asn_length + (bufp - data);
    return bufp + asn_length;
}

u_char         *
snmp_comstr_parse(u_char * data,
                  size_t * length,
                  u_char * community, size_t * community_len, long *version)
{
    u_char          type;
    long            ver;
    size_t          origlen = *community_len;

    /*
     * Message is an ASN.1 SEQUENCE.
     */
    data = asn_parse_sequence(data, length, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                              "auth message");
    if (data == NULL) {
        return NULL;
    }

    /*
     * First field is the version.
     */
    data = asn_parse_int(data, length, &type, &ver, sizeof(ver));
    *version = ver;
    if (data == NULL) {
        std::cout << "bad parse of version" << std::endl;
        return NULL;
    }

    /*
     * second field is the community string for SNMPv1 & SNMPv2c
     */
    data = asn_parse_string(data, length, &type, community, community_len);
    if (data == NULL) {
        std::cout << "bad parse of community" << std::endl;
        return NULL;
    }
    community[SNMP_MIN(*community_len, origlen - 1)] = '\0';
    return (u_char *) data;

}

u_char         *
asn_parse_objid(u_char * data,
                size_t * datalength,
                u_char * type, oid * objid, size_t * objidlength)
{
    /*
     * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
     * subidentifier ::= {leadingbyte}* lastbyte
     * leadingbyte ::= 1 7bitvalue
     * lastbyte ::= 0 7bitvalue
     */
    u_char *bufp = data;
    oid   *oidp = objid + 1;
    u_long subidentifier;
    long   length;
    u_long          asn_length;
    size_t          original_length = *objidlength;

    if (NULL == data || NULL == datalength || NULL == type || NULL == objid) {
        std::cout << "parse objid: NULL pointer" << std::endl;
        return NULL;
    }

    /** need at least 2 bytes to work with: type, length (which might be 0)  */
    if (*datalength < 2) {
        std::cout << "parse objid: datalength < 2" << std::endl;
        return NULL;
    }

    *type = *bufp++;
    if (*type != ASN_OBJECT_ID) {
        std::cout << "parse objid: wrong type" << std::endl;
        return NULL;
    }
    bufp = asn_parse_nlength(bufp, *datalength - 1, &asn_length);
    if (NULL == bufp) {
        std::cout << "parse objid: *datalength - 1" << std::endl;
        return NULL;
    }

    *datalength -= (int) asn_length + (bufp - data);

    /*
     * Handle invalid object identifier encodings of the form 06 00 robustly
     */
    if (asn_length == 0)
        objid[0] = objid[1] = 0;

    length = asn_length;
    (*objidlength)--;           /* account for expansion of first byte */

    while (length > 0 && (*objidlength)-- > 0) {
        subidentifier = 0;
        do {                    /* shift and add in low order 7 bits */
            subidentifier =
                (subidentifier << 7) + (*(u_char *) bufp & ~ASN_BIT8);
            length--;
        } while ((*(u_char *) bufp++ & ASN_BIT8) && (length > 0));        /* last byte has high bit clear */

    if (length == 0) {
            u_char *last_byte = bufp - 1;
            if (*last_byte & ASN_BIT8) {
                /* last byte has high bit set -> wrong BER encoded OID */
                std::cout << "subidentifier syntax error"<< std::endl;
                return NULL;
            }
        }
        if (subidentifier > MAX_SUBID) {
            std::cout << "subidentifier too large"<< std::endl;
            return NULL;
        }
        *oidp++ = (oid) subidentifier;
    }

    if (length || oidp < objid + 1) {
        std::cout << "OID length exceeds buffer size" << std::endl;
        *objidlength = original_length;
        return NULL;
    }

    /*
     * The first two subidentifiers are encoded into the first component
     * with the value (X * 40) + Y, where:
     *  X is the value of the first subidentifier.
     *  Y is the value of the second subidentifier.
     */
    subidentifier = oidp - objid >= 2 ? objid[1] : 0;
    if (subidentifier == 0x2B) {
        objid[0] = 1;
        objid[1] = 3;
    } else {
        if (subidentifier < 40) {
            objid[0] = 0;
            objid[1] = subidentifier;
        } else if (subidentifier < 80) {
            objid[0] = 1;
            objid[1] = subidentifier - 40;
        } else {
            objid[0] = 2;
            objid[1] = subidentifier - 80;
        }
    }

    *objidlength = (int) (oidp - objid);
    return bufp;
}

u_char         *
snmp_parse_var_op(u_char * data,
                  oid * var_name,
                  size_t * var_name_len,
                  u_char * var_val_type,
                  size_t * var_val_len,
                  u_char ** var_val, size_t * listlength)
{
    u_char          var_op_type;
    size_t          var_op_len = *listlength;
    u_char         *var_op_start = data;

    data = asn_parse_sequence(data, &var_op_len, &var_op_type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR), "var_op");
    if (data == NULL) {
        /*
         * msg detail is set
         */
        return NULL;
    }
    data =
        asn_parse_objid(data, &var_op_len, &var_op_type, var_name,
                        var_name_len);
    if (data == NULL) {
        std::cout << "No OID for variable" << std::endl;
        return NULL;
    }
    if (var_op_type !=
        (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID))
        return NULL;
    *var_val = data;            /* save pointer to this object */
    /*
     * find out what type of object this is
     */
    data = asn_parse_header(data, &var_op_len, var_val_type);
    if (data == NULL) {
        std::cout << "No header for value" << std::endl;
        return NULL;
    }
    /*
     * XXX no check for type!
     */
    *var_val_len = var_op_len;
    data += var_op_len;
    *listlength -= (int) (data - var_op_start);
    return data;
}

int
snmp_set_var_objid(netsnmp_variable_list * vp,
                   const oid * objid, size_t name_length){
    size_t          len = sizeof(oid) * name_length;

    if (vp->name != vp->name_loc && vp->name != NULL) {
        /*
         * Probably previously-allocated "big storage".  Better free it
         * else memory leaks possible.
         */
        free(vp->name);
    }

    /*
     * use built-in storage for smaller values
     */
    if (len <= sizeof(vp->name_loc)) {
        vp->name = vp->name_loc;
    } else {
        vp->name = (oid *) malloc(len);
        if (!vp->name)
            return 1;
    }
    if (objid)
        memmove(vp->name, objid, len);
    vp->name_length = name_length;
    return 0;
}

u_char* asn_parse_unsigned_int64(u_char * data,
                         size_t * datalength,
                         u_char * type,
                         struct counter64 *cp, size_t countersize){
    /*
     * ASN.1 integer ::= 0x02 asnlength byte {byte}*
     */
    //static const char *errpre = "parse uint64";
    const int       uint64sizelimit = (4 * 2) + 1;
    u_char *bufp = data;
    u_long          asn_length;
    u_long low = 0, high = 0;

    if (countersize != sizeof(struct counter64)) {
        //_asn_size_err(errpre, countersize, sizeof(struct counter64));
        return NULL;
    }

    if (NULL == data || NULL == datalength || NULL == type || NULL == cp) {
        //ERROR_MSG("parse uint64: NULL pointer");
        return NULL;
    }

    /** need at least 2 bytes to work with: type, length (which might be 0)  */
    if (*datalength < 2) {
        //_asn_short_err(errpre, *datalength, 2);
        return NULL;
    }

    *type = *bufp++;
    if (*type != ASN_COUNTER64) {
        //_asn_type_err(errpre, *type);
        return NULL;
    }
    bufp = asn_parse_nlength(bufp, *datalength - 1, &asn_length);
    if (NULL == bufp) {
        //_asn_short_err(errpre, *datalength - 1, asn_length);
        return NULL;
    }

    if (((int) asn_length > uint64sizelimit) ||
        (((int) asn_length == uint64sizelimit) && *bufp != 0x00)) {
        //_asn_length_err(errpre, (size_t) asn_length, uint64sizelimit);
        return NULL;
    }
    *datalength -= (int) asn_length + (bufp - data);
    while (asn_length--) {
        high = ((0x00FFFFFF & high) << 8) | ((low & 0xFF000000U) >> 24);
        low = ((low & 0x00FFFFFF) << 8) | *bufp++;
    }

    //CHECK_OVERFLOW_U(high,6);
    //CHECK_OVERFLOW_U(low,6);

    cp->low = low;
    cp->high = high;
    return bufp;
}

u_char         *
asn_parse_bitstring(u_char * data,
                    size_t * datalength,
                    u_char * type, u_char * str, size_t * strlength)
{
    /*
     * bitstring ::= 0x03 asnlength unused {byte}*
     */
    //static const char *errpre = "parse bitstring";
    u_char *bufp = data;
    u_long          asn_length;

    if (NULL == data || NULL == datalength || NULL == type ||
        NULL == str || NULL == strlength) {
        //ERROR_MSG("parse bitstring: NULL pointer");
        return NULL;
    }

    /** need at least 2 bytes to work with: type, length (which might be 0)  */
    if (*datalength < 2) {
        //_asn_short_err(errpre, *datalength, 2);
        return NULL;
    }

    *type = *bufp++;
    if (*type != ASN_BIT_STR) {
        //_asn_type_err(errpre, *type);
        return NULL;
    }

    bufp = asn_parse_nlength(bufp, *datalength - 1, &asn_length);
    if (NULL == bufp) {
        //_asn_short_err(errpre, *datalength - 1, asn_length);
        return NULL;
    }

    if ((size_t) asn_length > *strlength) {
        //_asn_length_err(errpre, (size_t) asn_length, *strlength);
        return NULL;
    }
    /*if (_asn_bitstring_check(errpre, asn_length, *bufp))
        return NULL;*/

    memmove(str, bufp, asn_length);
    *strlength = (int) asn_length;
    *datalength -= (int) asn_length + (bufp - data);
    return bufp + asn_length;
}

u_char* get_preceding_fields(u_char* data, size_t* length, u_char* type, snmp_pdu* pdu){
    /*
    * request id
    */
    data = asn_parse_int(data, length, type, &pdu->reqid,
                                 sizeof(pdu->reqid));
    if (data == NULL) {
       std::cout << "wrong req id" << std::endl;
       return NULL;
    }

    /*
    * error status (getbulk non-repeaters)
    */
    data = asn_parse_int(data, length, type, &pdu->errstat,
                                 sizeof(pdu->errstat));
    if (data == NULL) {
      std::cout << "wrong error status" << std::endl;
      return NULL;
    }

    /*
    * error index (getbulk max-repetitions)
    */

     data = asn_parse_int(data, length, type, &pdu->errindex,
                                 sizeof(pdu->errindex));
     if (data == NULL) {
       return NULL;
     }

     return (u_char *) data;
}

/**
 * Duplicates a memory block.
 *
 * @param[in] from Pointer to copy memory from.
 * @param[in] size Size of the data to be copied.
 *
 * @return Pointer to the duplicated memory block, or NULL if memory allocation
 * failed.
 */
void *netsnmp_memdup(const void *from, size_t size){
    void *to = NULL;

    if (from) {
        to = malloc(size);
        if (to)
            memcpy(to, from, size);
    }
    return to;
}

void get_var_bind_sequences(u_char* data, size_t* length, snmp_pdu* pdu){
    size_t          len;
    u_char         *p;
    netsnmp_variable_list* vp = NULL, *vplast = NULL;
    oid             objid[MAX_OID_LEN];
    u_char* var_val;
    if (data == NULL){
        //goto fail;
        std::cout << "null data" << std::endl;
    }
    /*
    * get each varBind sequence
    */
    while ((int) *length > 0) {
      vp = SNMP_MALLOC_TYPEDEF(netsnmp_variable_list);
      if (NULL == vp){
          //goto fail;
          std::cout << "no vp" << std::endl;
      }

      vp->name_length = MAX_OID_LEN;
      data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type,
                                     &vp->val_len, &var_val, length);
      if (data == NULL){
        std::cout << "data is null" << std::endl;
         //goto fail;
      }
      if (snmp_set_var_objid(vp, objid, vp->name_length)){
        //goto fail;
      }

      len = SNMP_MAX_PACKET_LEN;
      switch ((short) vp->type) {
        case ASN_INTEGER:
          vp->val.integer = (long *) vp->buf;
          vp->val_len = sizeof(long);
          p = asn_parse_int(var_val, &len, &vp->type,
                              (long *) vp->val.integer,
                              sizeof(*vp->val.integer));
          if (!p){
            //goto fail;
          }
                break;
        case ASN_COUNTER:
        case ASN_GAUGE:
        case ASN_TIMETICKS:
        case ASN_COUNTER64:
          vp->val.counter64 = (struct counter64 *) vp->buf;
          vp->val_len = sizeof(struct counter64);
          p = asn_parse_unsigned_int64(var_val, &len, &vp->type,
                                         (struct counter64 *) vp->val.
                                         counter64, vp->val_len);
          if (!p)
            //goto fail;
            break;
          case ASN_IPADDRESS:
            if (vp->val_len != 4){
                return;
            }

              //goto fail;
              /* fallthrough */
          case ASN_OCTET_STR:
                if (vp->val_len < sizeof(vp->buf)) {
                   vp->val.string = (u_char *) vp->buf;
                } else {
                   vp->val.string = (u_char *) malloc(vp->val_len);
                }
                if (vp->val.string == NULL) {
                               //goto fail;
                    std::cout << "val.string == NULL" << std::endl;
                }
                p = asn_parse_string(var_val, &len, &vp->type, vp->val.string,
                                             &vp->val_len);
                if (!p){
                    std::cout << "not p in string" << std::endl;
              //goto fail;
                }
                break;
          case ASN_OBJECT_ID:
                vp->val_len = MAX_OID_LEN;
                p = asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
                if (!p){
                    std::cout << "Not p" << std::endl;
                }
                    //goto fail;
                vp->val_len *= sizeof(oid);
                vp->val.objid = static_cast<unsigned long*>(netsnmp_memdup(objid, vp->val_len));
                if (vp->val.objid == NULL){
                    std::cout << "val.objid == NULL" << std::endl;
                }
                break;

            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
            case ASN_NULL:
                break;
            case ASN_BIT_STR:
                vp->val.bitstring = (u_char *) malloc(vp->val_len);
                if (vp->val.bitstring == NULL) {
                    //goto fail;
                }
                p = asn_parse_bitstring(var_val, &len, &vp->type,
                                    vp->val.bitstring, &vp->val_len);
                if (!p)
                    //goto fail;
                break;
            default:
                std::cout << "bad type returned" << std::endl;
                //snmp_log(LOG_ERR, "bad type returned (%x)\n", vp->type);
                //goto fail;
                break;
            }

            if (NULL == vplast) {
                pdu->variables = vp;
            } else {
                vplast->next_variable = vp;
            }
            vplast = vp;
            vp = NULL;
        }

}

int
snmp_oid_compare(const oid * in_name1,
                 size_t len1, const oid * in_name2, size_t len2)
{
    int    len;
    const oid *name1 = in_name1;
    const oid *name2 = in_name2;

    /*
     * len = minimum of len1 and len2
     */
    if (len1 < len2)
        len = len1;
    else
        len = len2;
    /*
     * find first non-matching OID
     */
    while (len-- > 0) {
        /*
         * these must be done in seperate comparisons, since
         * subtracting them and using that result has problems with
         * subids > 2^31.
         */
        if (*(name1) != *(name2)) {
            if (*(name1) < *(name2))
                return -1;
            return 1;
        }
        name1++;
        name2++;
    }
    /*
     * both OIDs equal up to length of shorter OID
     */
    if (len1 < len2)
        return -1;
    if (len2 < len1)
        return 1;
    return 0;
}

bool CheckTrapOid(snmp_pdu* pdu){
          netsnmp_variable_list *vars;
          oid snmpTrapOid[]    = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
          oid trapOid[MAX_OID_LEN+2] = {0};
          int trapOidLen;

          vars = pdu->variables;
          if (vars)
              vars = vars->next_variable;
          if (!vars || snmp_oid_compare(vars->name, vars->name_length,
                                        snmpTrapOid, OID_LENGTH(snmpTrapOid))) {
          /*
       * Didn't find it!
       * Let's look through the full list....
       */
      for ( vars = pdu->variables; vars; vars=vars->next_variable) {
                  if (!snmp_oid_compare(vars->name, vars->name_length,
                                        snmpTrapOid, OID_LENGTH(snmpTrapOid)))
                      break;
              }
              if (!vars) {
              /*
           * Still can't find it!  Give up.
           */
          std::cout << "Cannot find TrapOID in TRAP2 PDU\n" << std::endl;
          return false;
            }
            }
          memcpy(trapOid, vars->val.objid, vars->val_len);
          trapOidLen = vars->val_len /sizeof(oid);
          std::cout << "snmptrapd "<< trapOid << " " <<  trapOidLen << std::endl;
          return true;
}

