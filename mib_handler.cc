#include "mib_handler.h"

#include <iostream>

/*
 * Copies src to the dest buffer. The copy will never overflow the dest buffer
 * and dest will always be null terminated, len is the size of the dest buffer.
 *
 * Returns the length of the src buffer.
 */
size_t
strlcpy(char *dest, const char *src, size_t len)
{
    size_t src_len = strlen(src);
    size_t new_len;

    if (len == 0) {
        return (src_len);
    }

        if (src_len >= len) {
        new_len = len - 1;
    } else {
                new_len = src_len;
    }

        memcpy(dest, src, new_len);
    dest[new_len] = '\0';
    return (src_len);
}

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
    char *d = dst;
    const char *s = src;
    size_t n = siz;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end */
    while (n-- != 0 && *d != '\0')
        d++;
    dlen = d - dst;
    n = siz - dlen;

    if (n == 0)
        return(dlen + strlen(s));
    while (*s != '\0') {
        if (n != 1) {
            *d++ = *s;
            n--;
        }
        s++;
    }
    *d = '\0';

    return(dlen + (s - src));	/* count does not include NUL */
}

/**
 * This function increase the size of the buffer pointed at by *buf, which is
 * initially of size *buf_len.  Contents are preserved **AT THE BOTTOM END OF
 * THE BUFFER**.  If memory can be (re-)allocated then it returns 1, else it
 * returns 0.
 *
 * @param buf  pointer to a buffer pointer
 * @param buf_len      pointer to current size of buffer in bytes
 *
 * @note
 * The current re-allocation algorithm is to increase the buffer size by
 * whichever is the greater of 256 bytes or the current buffer size, up to
 * a maximum increase of 8192 bytes.
 */
int
snmp_realloc(u_char ** buf, size_t * buf_len)
{
    u_char         *new_buf = NULL;
    size_t          new_buf_len = 0;

    if (buf == NULL) {
        return 0;
    }

    if (*buf_len <= 255) {
        new_buf_len = *buf_len + 256;
    } else if (*buf_len > 255 && *buf_len <= 8191) {
        new_buf_len = *buf_len * 2;
    } else if (*buf_len > 8191) {
        new_buf_len = *buf_len + 8192;
    }

    if (*buf == NULL) {
        new_buf = (u_char *) malloc(new_buf_len);
    } else {
        new_buf = (u_char *) realloc(*buf, new_buf_len);
    }

    if (new_buf != NULL) {
        *buf = new_buf;
        *buf_len = new_buf_len;
        return 1;
    } else {
        return 0;
    }
}

int
snmp_strcat(u_char ** buf, size_t * buf_len, size_t * out_len,
            int allow_realloc, const u_char * s)
{
    if (buf == NULL || buf_len == NULL || out_len == NULL) {
        return 0;
    }

    if (s == NULL) {
        /*
         * Appending a NULL string always succeeds since it is a NOP.
         */
        return 1;
    }

    while ((*out_len + strlen((const char *) s) + 1) >= *buf_len) {
        if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
            return 0;
        }
    }

    if (!*buf)
        return 0;

    strcpy((char *) (*buf + *out_len), (const char *) s);
    *out_len += strlen((char *) (*buf + *out_len));
    return 1;
}

static int
name_hash(const char *name)
{
    int             hash = 0;
    const char     *cp;

    if (!name)
        return 0;
    for (cp = name; *cp; cp++)
        hash += tolower((unsigned char)(*cp));
    return (hash);
}


static void
build_translation_table(void)
{
    int             count;

    for (count = 0; count < 256; count++) {
        switch (count) {
        case OBJID:
            translation_table[count] = TYPE_OBJID;
            break;
        case OCTETSTR:
            translation_table[count] = TYPE_OCTETSTR;
            break;
        case INTEGER:
            translation_table[count] = TYPE_INTEGER;
            break;
        case NETADDR:
            translation_table[count] = TYPE_NETADDR;
            break;
        case IPADDR:
            translation_table[count] = TYPE_IPADDR;
            break;
        case COUNTER:
            translation_table[count] = TYPE_COUNTER;
            break;
        case GAUGE:
            translation_table[count] = TYPE_GAUGE;
            break;
        case TIMETICKS:
            translation_table[count] = TYPE_TIMETICKS;
            break;
        case KW_OPAQUE:
            translation_table[count] = TYPE_OPAQUE;
            break;
        case NUL:
            translation_table[count] = TYPE_NULL;
            break;
        case COUNTER64:
            translation_table[count] = TYPE_COUNTER64;
            break;
        case BITSTRING:
            translation_table[count] = TYPE_BITSTRING;
            break;
        case NSAPADDRESS:
            translation_table[count] = TYPE_NSAPADDRESS;
            break;
        case INTEGER32:
            translation_table[count] = TYPE_INTEGER32;
            break;
        case UINTEGER32:
            translation_table[count] = TYPE_UINTEGER;
            break;
        case UNSIGNED32:
            translation_table[count] = TYPE_UNSIGNED32;
            break;
        case TRAPTYPE:
            translation_table[count] = TYPE_TRAPTYPE;
            break;
        case NOTIFTYPE:
            translation_table[count] = TYPE_NOTIFTYPE;
            break;
        case NOTIFGROUP:
            translation_table[count] = TYPE_NOTIFGROUP;
            break;
        case OBJGROUP:
            translation_table[count] = TYPE_OBJGROUP;
            break;
        case MODULEIDENTITY:
            translation_table[count] = TYPE_MODID;
            break;
        case OBJIDENTITY:
            translation_table[count] = TYPE_OBJIDENTITY;
            break;
        case AGENTCAP:
            translation_table[count] = TYPE_AGENTCAP;
            break;
        case COMPLIANCE:
            translation_table[count] = TYPE_MODCOMP;
            break;
        default:
            translation_table[count] = TYPE_OTHER;
            break;
        }
    }
}

/*
 * module_name - copy module name to user buffer, return ptr to same.
 */
char           *
module_name(int modid, char *cp)
{
    struct module  *mp;

    for (mp = module_head; mp; mp = mp->next)
        if (mp->modid == modid) {
            strcpy(cp, mp->name);
            return (cp);
        }
    sprintf(cp, "#%d", modid);
    return (cp);
}


int
which_module(const char *name)
{
    struct module  *mp;

    for (mp = module_head; mp; mp = mp->next)
        if (!strcmp(mp->name, name))
            return (mp->modid);
    return (-1);
}

/**
 * Prints an integer according to the hint into a buffer.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      Address of the buffer to print to.
 * @param buf_len  Address to an integer containing the size of buf.
 * @param out_len  Incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param val      The variable to encode.
 * @param decimaltype 'd' or 'u' depending on integer type
 * @param hint     Contents of the DISPLAY-HINT clause of the MIB.
 *                 See RFC 1903 Section 3.1 for details. may _NOT_ be NULL.
 * @param units    Contents of the UNITS clause of the MIB. may be NULL.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_hinted_integer(u_char ** buf, size_t * buf_len,
                              size_t * out_len, int allow_realloc,
                              long val, const char decimaltype,
                              const char *hint, const char *units)
{
    char            fmt[10] = "%l@", tmp[256];
    int             shift = 0, len, negative = 0;

    if (hint[0] == 'd') {
        /*
         * We might *actually* want a 'u' here.
         */
        if (hint[1] == '-')
            shift = atoi(hint + 2);
        fmt[2] = decimaltype;
        if (val < 0) {
            negative = 1;
            val = -val;
        }
    } else {
        /*
         * DISPLAY-HINT character is 'b', 'o', or 'x'.
         */
        fmt[2] = hint[0];
    }

    if (hint[0] == 'b') {
    unsigned long int bit = 0x80000000LU;
    char *bp = tmp;
    while (bit) {
        *bp++ = val & bit ? '1' : '0';
        bit >>= 1;
    }
    *bp = 0;
    }
    else
    sprintf(tmp, fmt, val);

    if (shift != 0) {
        len = strlen(tmp);
        if (shift <= len) {
            tmp[len + 1] = 0;
            while (shift--) {
                tmp[len] = tmp[len - 1];
                len--;
            }
            tmp[len] = '.';
        } else {
            tmp[shift + 1] = 0;
            while (shift) {
                if (len-- > 0) {
                    tmp[shift] = tmp[len];
                } else {
                    tmp[shift] = '0';
                }
                shift--;
            }
            tmp[0] = '.';
        }
    }
    if (negative) {
        len = strlen(tmp)+1;
        while (len) {
            tmp[len] = tmp[len-1];
            len--;
        }
        tmp[0] = '-';
    }
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, (u_char *)tmp);
}



/**
 * Prints an integer into a buffer.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      Address of the buffer to print to.
 * @param buf_len  Address to an integer containing the size of buf.
 * @param out_len  Incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param var      The variable to encode.
 * @param enums    The enumeration ff this variable is enumerated. may be NULL.
 * @param hint     Contents of the DISPLAY-HINT clause of the MIB.
 *                 See RFC 1903 Section 3.1 for details. may be NULL.
 * @param units    Contents of the UNITS clause of the MIB. may be NULL.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_integer(u_char ** buf, size_t * buf_len, size_t * out_len,
                       int allow_realloc,
                       const netsnmp_variable_list * var,
                       const struct enum_list *enums,
                       const char *hint, const char *units)
{
    char           *enum_string = NULL;

    if (var->type != ASN_INTEGER) {
        if (!netsnmp_ds_get_boolean(
                NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)) {
            u_char          str[] = "Wrong Type (should be INTEGER): ";
            if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
                return 0;
        }
        return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
    }

    for (; enums; enums = enums->next) {
        if (enums->value == *var->val.integer) {
            enum_string = enums->label;
            break;
        }
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc,
                         (const u_char *) "INTEGER: ")) {
            return 0;
        }
    }

    if (enum_string == NULL ||
        netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM)) {
        if (hint) {
            if (!(sprint_realloc_hinted_integer(buf, buf_len, out_len,
                                                allow_realloc,
                                                *var->val.integer, 'd',
                                                hint, units))) {
                return 0;
            }
        } else {
            char            str[32];
            snprintf(str, sizeof(str), "%ld", *var->val.integer);
            if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) str)) {
                return 0;
            }
        }
    } else if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
        if (!snmp_strcat
            (buf, buf_len, out_len, allow_realloc,
             (const u_char *) enum_string)) {
            return 0;
        }
    } else {
        char            str[32];
        snprintf(str, sizeof(str), "(%ld)", *var->val.integer);
        if (!snmp_strcat
            (buf, buf_len, out_len, allow_realloc,
             (const u_char *) enum_string)) {
            return 0;
        }
        if (!snmp_strcat
            (buf, buf_len, out_len, allow_realloc, (const u_char *) str)) {
            return 0;
        }
    }

    if (units) {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}

/**
 * Prints an ascii string into a buffer.
 *
 * The characters pointed by *cp are encoded as an ascii string.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      address of the buffer to print to.
 * @param buf_len  address to an integer containing the size of buf.
 * @param out_len  incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param cp       the array of characters to encode.
 * @param len      the array length of cp.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_asciistring(u_char ** buf, size_t * buf_len,
                           size_t * out_len, int allow_realloc,
                           const u_char * cp, size_t len)
{
    int             i;

    for (i = 0; i < (int) len; i++) {
        if (isprint(*cp) || isspace(*cp)) {
            if (*cp == '\\' || *cp == '"') {
                if ((*out_len >= *buf_len) &&
                    !(allow_realloc && snmp_realloc(buf, buf_len))) {
                    return 0;
                }
                *(*buf + (*out_len)++) = '\\';
            }
            if ((*out_len >= *buf_len) &&
                !(allow_realloc && snmp_realloc(buf, buf_len))) {
                return 0;
            }
            *(*buf + (*out_len)++) = *cp++;
        } else {
            if ((*out_len >= *buf_len) &&
                !(allow_realloc && snmp_realloc(buf, buf_len))) {
                return 0;
            }
            *(*buf + (*out_len)++) = '.';
            cp++;
        }
    }
    if ((*out_len >= *buf_len) &&
        !(allow_realloc && snmp_realloc(buf, buf_len))) {
        return 0;
    }
    *(*buf + *out_len) = '\0';
    return 1;
}

/**
 * @internal
 * Prints the character pointed to if in human-readable ASCII range,
 * otherwise prints a dot.
 *
 * @param buf Buffer to print the character to.
 * @param ch  Character to print.
 */
static void
sprint_char(char *buf, const u_char ch)
{
    if (isprint(ch) || isspace(ch)) {
        sprintf(buf, "%c", (int) ch);
    } else {
        sprintf(buf, ".");
    }
}


/**
 * Prints a hexadecimal string into a buffer.
 *
 * The characters pointed by *cp are encoded as hexadecimal string.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      address of the buffer to print to.
 * @param buf_len  address to an integer containing the size of buf.
 * @param out_len  incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param cp       the array of characters to encode.
 * @param line_len the array length of cp.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
_sprint_hexstring_line(u_char ** buf, size_t * buf_len, size_t * out_len,
                       int allow_realloc, const u_char * cp, size_t line_len)
{
    const u_char   *tp;
    const u_char   *cp2 = cp;
    size_t          lenleft = line_len;

    /*
     * Make sure there's enough room for the hex output....
     */
    while ((*out_len + line_len*3+1) >= *buf_len) {
        if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
            return 0;
        }
    }

    /*
     * .... and display the hex values themselves....
     */
    for (; lenleft >= 8; lenleft-=8) {
        sprintf((char *) (*buf + *out_len),
                "%02X %02X %02X %02X %02X %02X %02X %02X ", cp[0], cp[1],
                cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
        *out_len += strlen((char *) (*buf + *out_len));
        cp       += 8;
    }
    for (; lenleft > 0; lenleft--) {
        sprintf((char *) (*buf + *out_len), "%02X ", *cp++);
        *out_len += strlen((char *) (*buf + *out_len));
    }

    /*
     * .... plus (optionally) do the same for the ASCII equivalent.
     */
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_HEX_TEXT)) {
        while ((*out_len + line_len+5) >= *buf_len) {
            if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
                return 0;
            }
        }
        sprintf((char *) (*buf + *out_len), "  [");
        *out_len += strlen((char *) (*buf + *out_len));
        for (tp = cp2; tp < cp; tp++) {
            sprint_char((char *) (*buf + *out_len), *tp);
            (*out_len)++;
        }
        sprintf((char *) (*buf + *out_len), "]");
        *out_len += strlen((char *) (*buf + *out_len));
    }
    return 1;
}


int
sprint_realloc_hexstring(u_char ** buf, size_t * buf_len, size_t * out_len,
                         int allow_realloc, const u_char * cp, size_t len)
{
    int line_len = netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                                      NETSNMP_DS_LIB_HEX_OUTPUT_LENGTH);
    if (line_len <= 0)
        line_len = len;

    for (; (int)len > line_len; len -= line_len) {
        if(!_sprint_hexstring_line(buf, buf_len, out_len, allow_realloc, cp, line_len))
            return 0;
        *(*buf + (*out_len)++) = '\n';
        *(*buf + *out_len) = 0;
        cp += line_len;
    }
    if(!_sprint_hexstring_line(buf, buf_len, out_len, allow_realloc, cp, len))
        return 0;
    *(*buf + *out_len) = 0;
    return 1;
}


/**
 * Prints an octet string into a buffer.
 *
 * The variable var is encoded as octet string.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      Address of the buffer to print to.
 * @param buf_len  Address to an integer containing the size of buf.
 * @param out_len  Incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param var      The variable to encode.
 * @param enums    The enumeration ff this variable is enumerated. may be NULL.
 * @param hint     Contents of the DISPLAY-HINT clause of the MIB.
 *                 See RFC 1903 Section 3.1 for details. may be NULL.
 * @param units    Contents of the UNITS clause of the MIB. may be NULL.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_octet_string(u_char ** buf, size_t * buf_len,
                            size_t * out_len, int allow_realloc,
                            const netsnmp_variable_list * var,
                            const struct enum_list *enums, const char *hint,
                            const char *units)
{
    size_t          saved_out_len = *out_len;
    const char     *saved_hint = hint;
    int             hex = 0, x = 0;
    u_char         *cp;
    int             output_format, cnt;

    if (var->type != ASN_OCTET_STR) {
        if (!netsnmp_ds_get_boolean(
                    NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)) {
            const char      str[] = "Wrong Type (should be OCTET STRING): ";
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, str))
                return 0;
        }
        return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
    }


    if (hint) {
        int             repeat, width = 1;
        long            value;
        char            code = 'd', separ = 0, term = 0, ch, intbuf[32];
#define HEX2DIGIT_NEED_INIT 3
        char            hex2digit = HEX2DIGIT_NEED_INIT;
        u_char         *ecp;

        if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "STRING: ")) {
                return 0;
            }
        }
        cp = var->val.string;
        ecp = cp + var->val_len;

        while (cp < ecp) {
            repeat = 1;
            if (*hint) {
                if (*hint == '*') {
                    repeat = *cp++;
                    hint++;
                }
                width = 0;
                while ('0' <= *hint && *hint <= '9')
                    width = (width * 10) + (*hint++ - '0');
                code = *hint++;
                if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
                    && (width != 0
                        || (ch != 'x' && ch != 'd' && ch != 'o')))
                    separ = *hint++;
                else
                    separ = 0;
                if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
                    && (width != 0
                        || (ch != 'x' && ch != 'd' && ch != 'o')))
                    term = *hint++;
                else
                    term = 0;
                if (width == 0)  /* Handle malformed hint strings */
                    width = 1;
            }

            while (repeat && cp < ecp) {
                value = 0;
                if (code != 'a' && code != 't') {
                    for (x = 0; x < width; x++) {
                        value = value * 256 + *cp++;
                    }
                }
                switch (code) {
                case 'x':
                    if (HEX2DIGIT_NEED_INIT == hex2digit)
                        hex2digit = netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                                           NETSNMP_DS_LIB_2DIGIT_HEX_OUTPUT);
                    /*
                     * if value is < 16, it will be a single hex digit. If the
                     * width is 1 (we are outputting a byte at a time), pat it
                     * to 2 digits if NETSNMP_DS_LIB_2DIGIT_HEX_OUTPUT is set
                     * or all of the following are true:
                     *  - we do not have a separation character
                     *  - there is no hint left (or there never was a hint)
                     *
                     * e.g. for the data 0xAA01BB, would anyone really ever
                     * want the string "AA1BB"??
                     */
                    if (((value < 16) && (1 == width)) &&
                        (hex2digit || ((0 == separ) && (0 == *hint)))) {
                        sprintf(intbuf, "0%lx", value);
                    } else {
                        sprintf(intbuf, "%lx", value);
                    }
                    if (!snmp_cstrcat
                        (buf, buf_len, out_len, allow_realloc, intbuf)) {
                        return 0;
                    }
                    break;
                case 'd':
                    sprintf(intbuf, "%ld", value);
                    if (!snmp_cstrcat
                        (buf, buf_len, out_len, allow_realloc, intbuf)) {
                        return 0;
                    }
                    break;
                case 'o':
                    sprintf(intbuf, "%lo", value);
                    if (!snmp_cstrcat
                        (buf, buf_len, out_len, allow_realloc, intbuf)) {
                        return 0;
                    }
                    break;
                case 't': /* new in rfc 3411 */
                case 'a':
                    /* A string hint gives the max size - we may not need this much */
                    cnt = SNMP_MIN(width, ecp - cp);
                    while ((*out_len + cnt + 1) > *buf_len) {
                        if (!allow_realloc || !snmp_realloc(buf, buf_len))
                            return 0;
                    }
                    if (memchr(cp, '\0', cnt) == NULL) {
                        /* No embedded '\0' - use memcpy() to preserve UTF-8 */
                        memcpy(*buf + *out_len, cp, cnt);
                        *out_len += cnt;
                        *(*buf + *out_len) = '\0';
                    } else if (!sprint_realloc_asciistring(buf, buf_len,
                                     out_len, allow_realloc, cp, cnt)) {
                        return 0;
                    }
                    cp += cnt;
                    break;
                default:
                    *out_len = saved_out_len;
                    if (snmp_cstrcat(buf, buf_len, out_len, allow_realloc,
                                     "(Bad hint ignored: ")
                        && snmp_cstrcat(buf, buf_len, out_len,
                                       allow_realloc, saved_hint)
                        && snmp_cstrcat(buf, buf_len, out_len,
                                       allow_realloc, ") ")) {
                        return sprint_realloc_octet_string(buf, buf_len,
                                                           out_len,
                                                           allow_realloc,
                                                           var, enums,
                                                           NULL, NULL);
                    } else {
                        return 0;
                    }
                }

                if (cp < ecp && separ) {
                    while ((*out_len + 1) >= *buf_len) {
                        if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
                            return 0;
                        }
                    }
                    *(*buf + *out_len) = separ;
                    (*out_len)++;
                    *(*buf + *out_len) = '\0';
                }
                repeat--;
            }

            if (term && cp < ecp) {
                while ((*out_len + 1) >= *buf_len) {
                    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
                        return 0;
                    }
                }
                *(*buf + *out_len) = term;
                (*out_len)++;
                *(*buf + *out_len) = '\0';
            }
        }

        if (units) {
            return (snmp_cstrcat
                    (buf, buf_len, out_len, allow_realloc, " ")
                    && snmp_cstrcat(buf, buf_len, out_len, allow_realloc, units));
        }
        if ((*out_len >= *buf_len) &&
            !(allow_realloc && snmp_realloc(buf, buf_len))) {
            return 0;
        }
        *(*buf + *out_len) = '\0';

        return 1;
    }

    output_format = netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_STRING_OUTPUT_FORMAT);
    if (0 == output_format) {
        output_format = NETSNMP_STRING_OUTPUT_GUESS;
    }
    switch (output_format) {
    case NETSNMP_STRING_OUTPUT_GUESS:
        hex = 0;
        for (cp = var->val.string, x = 0; x < (int) var->val_len; x++, cp++) {
            if (!isprint(*cp) && !isspace(*cp)) {
                hex = 1;
            }
        }
        break;

    case NETSNMP_STRING_OUTPUT_ASCII:
        hex = 0;
        break;

    case NETSNMP_STRING_OUTPUT_HEX:
        hex = 1;
        break;
    }

    if (var->val_len == 0) {
        return snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "\"\"");
    }

    if (hex) {
        if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "\"")) {
                return 0;
            }
        } else {
            if (!snmp_cstrcat
                (buf, buf_len, out_len, allow_realloc, "Hex-STRING: ")) {
                return 0;
            }
        }

        if (!sprint_realloc_hexstring(buf, buf_len, out_len, allow_realloc,
                                      var->val.string, var->val_len)) {
            return 0;
        }

        if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "\"")) {
                return 0;
            }
        }
    } else {
        if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
            if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc,
                             "STRING: ")) {
                return 0;
            }
        }
        if (!snmp_cstrcat
            (buf, buf_len, out_len, allow_realloc, "\"")) {
            return 0;
        }
        if (!sprint_realloc_asciistring
            (buf, buf_len, out_len, allow_realloc, var->val.string,
             var->val_len)) {
            return 0;
        }
        if (!snmp_cstrcat(buf, buf_len, out_len, allow_realloc, "\"")) {
            return 0;
        }
    }

    if (units) {
        return (snmp_cstrcat(buf, buf_len, out_len, allow_realloc, " ")
                && snmp_cstrcat(buf, buf_len, out_len, allow_realloc, units));
    }
    return 1;
}

/**
 * Universal print routine, prints a variable into a buffer according to the variable
 * type.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      Address of the buffer to print to.
 * @param buf_len  Address to an integer containing the size of buf.
 * @param out_len  Incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param var      The variable to encode.
 * @param enums    The enumeration ff this variable is enumerated. may be NULL.
 * @param hint     Contents of the DISPLAY-HINT clause of the MIB.
 *                 See RFC 1903 Section 3.1 for details. may be NULL.
 * @param units    Contents of the UNITS clause of the MIB. may be NULL.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_by_type(u_char ** buf, size_t * buf_len, size_t * out_len,
                       int allow_realloc,
                       const netsnmp_variable_list * var,
                       const struct enum_list *enums,
                       const char *hint, const char *units)

{
    switch (var->type) {
    case ASN_INTEGER:
        return sprint_realloc_integer(buf, buf_len, out_len, allow_realloc,
                                      var, enums, hint, units);
    case ASN_OCTET_STR:
        return sprint_realloc_octet_string(buf, buf_len, out_len,
                                           allow_realloc, var, enums, hint,
                                           units);
    //case ASN_BIT_STR:
        //return sprint_realloc_bitstring(buf, buf_len, out_len,
                                       // allow_realloc, var, enums, hint,
                                       // units);*/
    case ASN_OBJECT_ID:
        return sprint_realloc_object_identifier(buf, buf_len, out_len,
                                                allow_realloc, var, enums,
                                                hint, units);
    case ASN_TIMETICKS:
        return sprint_realloc_timeticks(buf, buf_len, out_len,
                                      allow_realloc, var, enums, hint,
                                      units);

    //case ASN_GAUGE:
        //return sprint_realloc_gauge(buf, buf_len, out_len, allow_realloc,
                                    //var, enums, hint, units);
                                    return 0;
   // case ASN_COUNTER:
       // return sprint_realloc_counter(buf, buf_len, out_len, allow_realloc,
                                     // var, enums, hint, units);
         return 0;
    //case ASN_IPADDRESS:
        //return sprint_realloc_ipaddress(buf, buf_len, out_len,
                                       // allow_realloc, var, enums, hint,
                                        //units);
    //case ASN_NULL:
       // return sprint_realloc_null(buf, buf_len, out_len, allow_realloc,
                                  // var, enums, hint, units);

    //case ASN_UINTEGER:
        //return sprint_realloc_uinteger(buf, buf_len, out_len,
                                     // allow_realloc, var, enums, hint,
                                      // units);
    //case ASN_COUNTER64:
       // return sprint_realloc_counter64(buf, buf_len, out_len,
                                       // allow_realloc, var, enums, hint,
                                       // units);
    //default:
        //return sprint_realloc_badtype(buf, buf_len, out_len, allow_realloc,
                                      //var, enums, hint, units);
    }
}

struct tree    *
find_tree_node(const char *name, int modid)
{
    struct tree    *tp, *headtp;
    int             count, *int_p;

    if (!name || !*name)
        return (NULL);

    headtp = tbuckets[NBUCKET(name_hash(name))];
    for (tp = headtp; tp; tp = tp->next) {
        if (tp->label && !strcmp(tp->label, name)) {

            if (modid == -1)    /* Any module */
                return (tp);

            for (int_p = tp->module_list, count = 0;
                 count < tp->number_modules; ++count, ++int_p)
                if (*int_p == modid)
                    return (tp);
        }
    }

    return (NULL);
}

static void
_get_realloc_symbol_octet_string(size_t numids, const oid * objid,
                 u_char ** buf, size_t * buf_len,
                 size_t * out_len, int allow_realloc,
                 int *buf_overflow, struct tree* tp)
{
  netsnmp_variable_list	var = { 0 };
  u_char		buffer[1024];
  size_t		i;

  for (i = 0; i < numids; i++)
    buffer[i] = (u_char) objid[i];
  var.type = ASN_OCTET_STR;
  var.val.string = buffer;
  var.val_len = numids;
  if (!*buf_overflow) {
    if (!sprint_realloc_octet_string(buf, buf_len, out_len,
                     allow_realloc, &var,
                     NULL, tp->hint,
                     NULL)) {
      *buf_overflow = 1;
    }
  }
}


int
dump_realloc_oid_to_string(const oid * objid, size_t objidlen,
                           u_char ** buf, size_t * buf_len,
                           size_t * out_len, int allow_realloc,
                           char quotechar)
{
    if (buf) {
        int             i, alen;

        for (i = 0, alen = 0; i < (int) objidlen; i++) {
            oid             tst = objid[i];
            if ((tst > 254) || (!isprint(tst))) {
                tst = (oid) '.';
            }

            if (alen == 0) {
                if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_ESCAPE_QUOTES)) {
                    while ((*out_len + 2) >= *buf_len) {
                        if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
                            return 0;
                        }
                    }
                    *(*buf + *out_len) = '\\';
                    (*out_len)++;
                }
                while ((*out_len + 2) >= *buf_len) {
                    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
                        return 0;
                    }
                }
                *(*buf + *out_len) = quotechar;
                (*out_len)++;
            }

            while ((*out_len + 2) >= *buf_len) {
                if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
                    return 0;
                }
            }
            *(*buf + *out_len) = (char) tst;
            (*out_len)++;
            alen++;
        }

        if (alen) {
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_ESCAPE_QUOTES)) {
                while ((*out_len + 2) >= *buf_len) {
                    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
                        return 0;
                    }
                }
                *(*buf + *out_len) = '\\';
                (*out_len)++;
            }
            while ((*out_len + 2) >= *buf_len) {
                if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
                    return 0;
                }
            }
            *(*buf + *out_len) = quotechar;
            (*out_len)++;
        }

        *(*buf + *out_len) = '\0';
    }

    return 1;
}

/*
 * translate integer tc_index to string identifier from tclist
 * *
 * * Returns pointer to string in table (should not be modified) or NULL
 */
const char     *
get_tc_descriptor(int tc_index)
{
    if (tc_index < 0 || tc_index >= tc_alloc)
        return NULL;
    return tclist[tc_index].descriptor;
}

/*
 * dump_realloc_oid_to_inetaddress:
 *   return 0 for failure,
 *   return 1 for success,
 *   return 2 for not handled
 */

int
dump_realloc_oid_to_inetaddress(const int addr_type, const oid * objid, size_t objidlen,
                                u_char ** buf, size_t * buf_len,
                                size_t * out_len, int allow_realloc,
                                char quotechar)
{
    int             i, len;
    char            intbuf[64], *p;
    char *const     end = intbuf + sizeof(intbuf);
    unsigned char  *zc;
    unsigned long   zone;

    if (!buf)
        return 1;

    for (i = 0; i < objidlen; i++)
        if (objid[i] > 255)
            return 2;

    p = intbuf;
    *p++ = quotechar;

    switch (addr_type) {
    case IPV4:
    case IPV4Z:
        if ((addr_type == IPV4  && objidlen != 4) ||
            (addr_type == IPV4Z && objidlen != 8))
            return 2;

        len = snprintf(p, end - p, "%" NETSNMP_PRIo "u.%" NETSNMP_PRIo "u."
                      "%" NETSNMP_PRIo "u.%" NETSNMP_PRIo "u",
                      objid[0], objid[1], objid[2], objid[3]);
        p += len;
        if (p >= end)
            return 2;
        if (addr_type == IPV4Z) {
            zc = (unsigned char*)&zone;
            zc[0] = objid[4];
            zc[1] = objid[5];
            zc[2] = objid[6];
            zc[3] = objid[7];
            zone = ntohl(zone);
            len = snprintf(p, end - p, "%%%lu", zone);
            p += len;
            if (p >= end)
                return 2;
        }

        break;

    case IPV6:
    case IPV6Z:
        if ((addr_type == IPV6 && objidlen != 16) ||
            (addr_type == IPV6Z && objidlen != 20))
            return 2;

        len = 0;
        for (i = 0; i < 16; i ++) {
            len = snprintf(p, end - p, "%s%02" NETSNMP_PRIo "x", i ? ":" : "",
                           objid[i]);
            p += len;
            if (p >= end)
                return 2;
        }

        if (addr_type == IPV6Z) {
            zc = (unsigned char*)&zone;
            zc[0] = objid[16];
            zc[1] = objid[17];
            zc[2] = objid[18];
            zc[3] = objid[19];
            zone = ntohl(zone);
            len = snprintf(p, end - p, "%%%lu", zone);
            p += len;
            if (p >= end)
                return 2;
        }

        break;

    case DNS:
    default:
        /* DNS can just be handled by dump_realloc_oid_to_string() */
        return 2;
    }

    *p++ = quotechar;
    if (p >= end)
        return 2;

    *p++ = '\0';
    if (p >= end)
        return 2;

    return snmp_cstrcat(buf, buf_len, out_len, allow_realloc, intbuf);
}

/**
 * Converts timeticks to hours, minutes, seconds string.
 *
 * @param timeticks    The timeticks to convert.
 * @param buf          Buffer to write to, has to be at
 *                     least 40 Bytes large.
 *
 * @return The buffer.
 */
static char    *
uptimeString(u_long timeticks, char *buf, size_t buflen)
{
    int             centisecs, seconds, minutes, hours, days;

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS)) {
        snprintf(buf, buflen, "%lu", timeticks);
        return buf;
    }


    centisecs = timeticks % 100;
    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT))
        snprintf(buf, buflen, "%d:%d:%02d:%02d.%02d",
                days, hours, minutes, seconds, centisecs);
    else {
        if (days == 0) {
            snprintf(buf, buflen, "%d:%02d:%02d.%02d",
                    hours, minutes, seconds, centisecs);
        } else if (days == 1) {
            snprintf(buf, buflen, "%d day, %d:%02d:%02d.%02d",
                    days, hours, minutes, seconds, centisecs);
        } else {
            snprintf(buf, buflen, "%d days, %d:%02d:%02d.%02d",
                    days, hours, minutes, seconds, centisecs);
        }
    }
    return buf;
}

void
_oid_finish_printing(const oid * objid, size_t objidlen,
                     u_char ** buf, size_t * buf_len, size_t * out_len,
                     int allow_realloc, int *buf_overflow) {
    char            intbuf[64];
    if (*buf != NULL && *(*buf + *out_len - 1) != '.') {
        if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                           allow_realloc,
                                           (const u_char *) ".")) {
            *buf_overflow = 1;
        }
    }

    while (objidlen-- > 0) {    /* output rest of name, uninterpreted */
        sprintf(intbuf, "%" NETSNMP_PRIo "u.", *objid++);
        if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                           allow_realloc,
                                           (const u_char *) intbuf)) {
            *buf_overflow = 1;
        }
    }

    if (*buf != NULL) {
        *(*buf + *out_len - 1) = '\0';  /* remove trailing dot */
        *out_len = *out_len - 1;
    }
}

static struct tree *
_get_realloc_symbol(const oid * objid, size_t objidlen,
                    struct tree *subtree,
                    u_char ** buf, size_t * buf_len, size_t * out_len,
                    int allow_realloc, int *buf_overflow,
                    struct index_list *in_dices, size_t * end_of_known)
{
    struct tree    *return_tree = NULL;
    int             extended_index =
        netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_EXTENDED_INDEX);
    int             output_format =
        netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT);
    char            intbuf[64];
    struct tree    *orgtree = subtree;

    if (!objid || !buf) {
        return NULL;
    }
    int counter = 0;
    for (; subtree; subtree = subtree->next_peer) {
        ++counter;
        if (*objid == subtree->subid) {
        while (subtree->next_peer && subtree->next_peer->subid == *objid)
        subtree = subtree->next_peer;
            if (subtree->indexes) {
                in_dices = subtree->indexes;
            } else if (subtree->augments) {
                struct tree    *tp2 =
                    find_tree_node(subtree->augments, -1);
                if (tp2) {
                    in_dices = tp2->indexes;
                }
            }

            if (!strncmp(subtree->label, ANON, ANON_LEN) ||
                (NETSNMP_OID_OUTPUT_NUMERIC == output_format)) {
                sprintf(intbuf, "%lu", subtree->subid);
                if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                                   allow_realloc,
                                                   (const u_char *)
                                                   intbuf)) {
                    *buf_overflow = 1;
                }
            } else {
                if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                                   allow_realloc,
                                                   (const u_char *)
                                                   subtree->label)) {
                    *buf_overflow = 1;
                }
            }

            if (objidlen > 1) {
                if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                                   allow_realloc,
                                                   (const u_char *) ".")) {
                    *buf_overflow = 1;
                }

                return_tree = _get_realloc_symbol(objid + 1, objidlen - 1,
                                                  subtree->child_list,
                                                  buf, buf_len, out_len,
                                                  allow_realloc,
                                                  buf_overflow, in_dices,
                                                  end_of_known);
            }

            if (return_tree != NULL) {
                return return_tree;
            } else {
                return subtree;
            }
        }
    }
    if (end_of_known) {
        *end_of_known = *out_len;
    }

    /*
     * Subtree not found.
     */

    if (orgtree && in_dices && objidlen > 0) {
    sprintf(intbuf, "%" NETSNMP_PRIo "u.", *objid);
    if (!*buf_overflow
        && !snmp_strcat(buf, buf_len, out_len,
                allow_realloc,
                (const u_char *) intbuf)) {
        *buf_overflow = 1;
    }
    objid++;
    objidlen--;
    }

    while (in_dices && (objidlen > 0) &&
           (NETSNMP_OID_OUTPUT_NUMERIC != output_format) &&
           !netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_BREAKDOWN_OIDS)) {
        size_t          numids;
        struct tree    *tp;

        tp = find_tree_node(in_dices->ilabel, -1);

        if (!tp) {
            /*
             * Can't find an index in the mib tree.  Bail.
             */
            goto finish_it;
        }

        if (extended_index) {
            if (*buf != NULL && *(*buf + *out_len - 1) == '.') {
                (*out_len)--;
            }
            if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                               allow_realloc,
                                               (const u_char *) "[")) {
                *buf_overflow = 1;
            }
        }

        switch (tp->type) {
        case TYPE_OCTETSTR:
            if (extended_index && tp->hint) {
                if (in_dices->isimplied) {
                    numids = objidlen;
                    if (numids > objidlen)
                        goto finish_it;
                } else if (tp->ranges && !tp->ranges->next
                           && tp->ranges->low == tp->ranges->high) {
                    numids = tp->ranges->low;
                    if (numids > objidlen)
                        goto finish_it;
                } else {
                    numids = *objid;
                    if (numids >= objidlen)
                        goto finish_it;
                    objid++;
                    objidlen--;
                }
                if (numids > objidlen)
                    goto finish_it;
        _get_realloc_symbol_octet_string(numids, objid, buf, buf_len,
                         out_len, allow_realloc,
                         buf_overflow, tp);
            } else if (in_dices->isimplied) {
                numids = objidlen;
                if (numids > objidlen)
                    goto finish_it;

                if (!*buf_overflow) {
                    if (!dump_realloc_oid_to_string
                        (objid, numids, buf, buf_len, out_len,
                         allow_realloc, '\'')) {
                        *buf_overflow = 1;
                    }
                }
            } else if (tp->ranges && !tp->ranges->next
                       && tp->ranges->low == tp->ranges->high) {
                /*
                 * a fixed-length octet string
                 */
                numids = tp->ranges->low;
                if (numids > objidlen)
                    goto finish_it;

                if (!*buf_overflow) {
                    if (!dump_realloc_oid_to_string
                        (objid, numids, buf, buf_len, out_len,
                         allow_realloc, '\'')) {
                        *buf_overflow = 1;
                    }
                }
            } else {
                numids = (size_t) * objid + 1;
                if (numids > objidlen)
                    goto finish_it;
                if (numids == 1) {
                    if (netsnmp_ds_get_boolean
                        (NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_ESCAPE_QUOTES)) {
                        if (!*buf_overflow
                            && !snmp_strcat(buf, buf_len, out_len,
                                            allow_realloc,
                                            (const u_char *) "\\")) {
                            *buf_overflow = 1;
                        }
                    }
                    if (!*buf_overflow
                        && !snmp_strcat(buf, buf_len, out_len,
                                        allow_realloc,
                                        (const u_char *) "\"")) {
                        *buf_overflow = 1;
                    }
                    if (netsnmp_ds_get_boolean
                        (NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_ESCAPE_QUOTES)) {
                        if (!*buf_overflow
                            && !snmp_strcat(buf, buf_len, out_len,
                                            allow_realloc,
                                            (const u_char *) "\\")) {
                            *buf_overflow = 1;
                        }
                    }
                    if (!*buf_overflow
                        && !snmp_strcat(buf, buf_len, out_len,
                                        allow_realloc,
                                        (const u_char *) "\"")) {
                        *buf_overflow = 1;
                    }
                } else {
                    if (!*buf_overflow) {
                        struct tree * next_peer;
                        int normal_handling = 1;

                        if (tp->next_peer) {
                            next_peer = tp->next_peer;
                        }

                        /* Try handling the InetAddress in the OID, in case of failure,
                         * use the normal_handling.
                         */
                        if (tp->next_peer &&
                            tp->tc_index != -1 &&
                            next_peer->tc_index != -1 &&
                            strcmp(get_tc_descriptor(tp->tc_index), "InetAddress") == 0 &&
                            strcmp(get_tc_descriptor(next_peer->tc_index),
                                    "InetAddressType") == 0 ) {

                            int ret;
                            int addr_type = *(objid - 1);

                            ret = dump_realloc_oid_to_inetaddress(addr_type,
                                        objid + 1, numids - 1, buf, buf_len, out_len,
                                        allow_realloc, '"');
                            if (ret != 2) {
                                normal_handling = 0;
                                if (ret == 0) {
                                    *buf_overflow = 1;
                                }

                            }
                        }
                        if (normal_handling && !dump_realloc_oid_to_string
                            (objid + 1, numids - 1, buf, buf_len, out_len,
                             allow_realloc, '"')) {
                            *buf_overflow = 1;
                        }
                    }
                }
            }
            objid += numids;
            objidlen -= numids;
            break;

        case TYPE_INTEGER32:
        case TYPE_UINTEGER:
        case TYPE_UNSIGNED32:
        case TYPE_GAUGE:
        case TYPE_INTEGER:
            if (tp->enums) {
                struct enum_list *ep = tp->enums;
                while (ep && ep->value != (int) (*objid)) {
                    ep = ep->next;
                }
                if (ep) {
                    if (!*buf_overflow
                        && !snmp_strcat(buf, buf_len, out_len,
                                        allow_realloc,
                                        (const u_char *) ep->label)) {
                        *buf_overflow = 1;
                    }
                } else {
                    sprintf(intbuf, "%" NETSNMP_PRIo "u", *objid);
                    if (!*buf_overflow
                        && !snmp_strcat(buf, buf_len, out_len,
                                        allow_realloc,
                                        (const u_char *) intbuf)) {
                        *buf_overflow = 1;
                    }
                }
            } else {
                sprintf(intbuf, "%" NETSNMP_PRIo "u", *objid);
                if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                                   allow_realloc,
                                                   (const u_char *)
                                                   intbuf)) {
                    *buf_overflow = 1;
                }
            }
            objid++;
            objidlen--;
            break;

        case TYPE_TIMETICKS:
            /* In an index, this is probably a timefilter */
            if (extended_index) {
                uptimeString( *objid, intbuf, sizeof( intbuf ) );
            } else {
                sprintf(intbuf, "%" NETSNMP_PRIo "u", *objid);
            }
            if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                               allow_realloc,
                                               (const u_char *)
                                               intbuf)) {
                *buf_overflow = 1;
            }
            objid++;
            objidlen--;
            break;

        case TYPE_OBJID:
            if (in_dices->isimplied) {
                numids = objidlen;
            } else {
                numids = (size_t) * objid + 1;
            }
            if (numids > objidlen)
                goto finish_it;
            if (extended_index) {
                if (in_dices->isimplied) {
                    if (!*buf_overflow
                        && !netsnmp_sprint_realloc_objid_tree(buf, buf_len,
                                                              out_len,
                                                              allow_realloc,
                                                              buf_overflow,
                                                              objid,
                                                              numids)) {
                        *buf_overflow = 1;
                    }
                } else {
                    if (!*buf_overflow
                        && !netsnmp_sprint_realloc_objid_tree(buf, buf_len,
                                                              out_len,
                                                              allow_realloc,
                                                              buf_overflow,
                                                              objid + 1,
                                                              numids -
                                                              1)) {
                        *buf_overflow = 1;
                    }
                }
            } else {
                _get_realloc_symbol(objid, numids, NULL, buf, buf_len,
                                    out_len, allow_realloc, buf_overflow,
                                    NULL, NULL);
            }
            objid += (numids);
            objidlen -= (numids);
            break;

        case TYPE_IPADDR:
            if (objidlen < 4)
                goto finish_it;
            sprintf(intbuf, "%" NETSNMP_PRIo "u.%" NETSNMP_PRIo "u."
                    "%" NETSNMP_PRIo "u.%" NETSNMP_PRIo "u",
                    objid[0], objid[1], objid[2], objid[3]);
            objid += 4;
            objidlen -= 4;
            if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                               allow_realloc,
                                               (const u_char *) intbuf)) {
                *buf_overflow = 1;
            }
            break;

        case TYPE_NETADDR:{
                oid             ntype = *objid++;

                objidlen--;
                sprintf(intbuf, "%" NETSNMP_PRIo "u.", ntype);
                if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                                   allow_realloc,
                                                   (const u_char *)
                                                   intbuf)) {
                    *buf_overflow = 1;
                }

                if (ntype == 1 && objidlen >= 4) {
                    sprintf(intbuf, "%" NETSNMP_PRIo "u.%" NETSNMP_PRIo "u."
                            "%" NETSNMP_PRIo "u.%" NETSNMP_PRIo "u",
                            objid[0], objid[1], objid[2], objid[3]);
                    if (!*buf_overflow
                        && !snmp_strcat(buf, buf_len, out_len,
                                        allow_realloc,
                                        (const u_char *) intbuf)) {
                        *buf_overflow = 1;
                    }
                    objid += 4;
                    objidlen -= 4;
                } else {
                    goto finish_it;
                }
            }
            break;

        case TYPE_NSAPADDRESS:
        default:
            goto finish_it;
            break;
        }

        if (extended_index) {
            if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                               allow_realloc,
                                               (const u_char *) "]")) {
                *buf_overflow = 1;
            }
        } else {
            if (!*buf_overflow && !snmp_strcat(buf, buf_len, out_len,
                                               allow_realloc,
                                               (const u_char *) ".")) {
                *buf_overflow = 1;
            }
        }
        in_dices = in_dices->next;
    }

  finish_it:
    _oid_finish_printing(objid, objidlen,
                         buf, buf_len, out_len,
                         allow_realloc, buf_overflow);
    return NULL;
}


struct tree    *
netsnmp_sprint_realloc_objid_tree(u_char ** buf, size_t * buf_len,
                                  size_t * out_len, int allow_realloc,
                                  int *buf_overflow,
                                  const oid * objid, size_t objidlen)
{
    u_char         *tbuf = NULL, *cp = NULL;
    size_t          tbuf_len = 512, tout_len = 0;
    struct tree    *subtree = tree_head;
    size_t          midpoint_offset = 0;
    int             tbuf_overflow = 0;
    int             output_format;

    if ((tbuf = (u_char *) calloc(tbuf_len, 1)) == NULL) {
        tbuf_overflow = 1;
    } else {
        *tbuf = '.';
        tout_len = 1;
    }

    subtree = _get_realloc_symbol(objid, objidlen, subtree,
                                  &tbuf, &tbuf_len, &tout_len,
                                  allow_realloc, &tbuf_overflow, NULL,
                                  &midpoint_offset);

    if (tbuf_overflow) {
        if (!*buf_overflow) {
            snmp_strcat(buf, buf_len, out_len, allow_realloc, tbuf);
            *buf_overflow = 1;
        }
        SNMP_FREE(tbuf);
        return subtree;
    }

    output_format = netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT);
    if (0 == output_format) {
        output_format = NETSNMP_OID_OUTPUT_MODULE;
    }
    switch (output_format) {
    case NETSNMP_OID_OUTPUT_FULL:
    case NETSNMP_OID_OUTPUT_NUMERIC:
        cp = tbuf;
        break;

    case NETSNMP_OID_OUTPUT_SUFFIX:
    case NETSNMP_OID_OUTPUT_MODULE:
        for (cp = tbuf; *cp; cp++);

        if (midpoint_offset != 0) {
            cp = tbuf + midpoint_offset - 2;    /*  beyond the '.'  */
        } else {
            while (cp >= tbuf) {
                if (isalpha(*cp)) {
                    break;
                }
                cp--;
            }
        }

        while (cp >= tbuf) {
            if (*cp == '.') {
                break;
            }
            cp--;
        }

        cp++;

        if ((NETSNMP_OID_OUTPUT_MODULE == output_format)
            && cp > tbuf) {
            char            modbuf[256] = { 0 }, *mod =
                module_name(subtree->modid, modbuf);

            /*
             * Don't add the module ID if it's just numeric (i.e. we couldn't look
             * it up properly.
             */

            if (!*buf_overflow && modbuf[0] != '#') {
                if (!snmp_strcat
                    (buf, buf_len, out_len, allow_realloc,
                     (const u_char *) mod)
                    || !snmp_strcat(buf, buf_len, out_len, allow_realloc,
                                    (const u_char *) "::")) {
                    *buf_overflow = 1;
                }
            }
        }
        break;

    case NETSNMP_OID_OUTPUT_UCD:
    {
        PrefixListPtr   pp = &mib_prefixes[0];
        size_t          ilen, tlen;
        const char     *testcp;

        cp = tbuf;
        tlen = strlen((char *) tbuf);

        while (pp->str) {
            ilen = pp->len;
            testcp = pp->str;

            if ((tlen > ilen) && memcmp(tbuf, testcp, ilen) == 0) {
                cp += (ilen + 1);
                break;
            }
            pp++;
        }
        break;
    }

    case NETSNMP_OID_OUTPUT_NONE:
    default:
        cp = NULL;
    }

    if (!*buf_overflow &&
        !snmp_strcat(buf, buf_len, out_len, allow_realloc, cp)) {
        *buf_overflow = 1;
    }
    SNMP_FREE(tbuf);
    return subtree;
}

/**
 * Prints an object identifier into a buffer.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      Address of the buffer to print to.
 * @param buf_len  Address to an integer containing the size of buf.
 * @param out_len  Incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param var      The variable to encode.
 * @param enums    The enumeration ff this variable is enumerated. may be NULL.
 * @param hint     Contents of the DISPLAY-HINT clause of the MIB.
 *                 See RFC 1903 Section 3.1 for details. may be NULL.
 * @param units    Contents of the UNITS clause of the MIB. may be NULL.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_object_identifier(u_char ** buf, size_t * buf_len,
                                 size_t * out_len, int allow_realloc,
                                 const netsnmp_variable_list * var,
                                 const struct enum_list *enums,
                                 const char *hint, const char *units)
{
    int             buf_overflow = 0;

    if (var->type != ASN_OBJECT_ID) {
        if (!netsnmp_ds_get_boolean(
                NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)) {
            u_char          str[] = "Wrong Type (should be OBJECT IDENTIFIER): ";
            if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
                return 0;
        }
        return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
    }

    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
        u_char          str[] = "OID: ";
        if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
            return 0;
        }
    }

    netsnmp_sprint_realloc_objid_tree(buf, buf_len, out_len, allow_realloc,
                                      &buf_overflow,
                                      (oid *) (var->val.objid),
                                      var->val_len / sizeof(oid));

    if (buf_overflow) {
        return 0;
    }

    if (units) {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}

/**
 * Prints a timetick variable into a buffer.
 *
 * If allow_realloc is true the buffer will be (re)allocated to fit in the
 * needed size. (Note: *buf may change due to this.)
 *
 * @param buf      Address of the buffer to print to.
 * @param buf_len  Address to an integer containing the size of buf.
 * @param out_len  Incremented by the number of characters printed.
 * @param allow_realloc if not zero reallocate the buffer to fit the
 *                      needed size.
 * @param var      The variable to encode.
 * @param enums    The enumeration ff this variable is enumerated. may be NULL.
 * @param hint     Contents of the DISPLAY-HINT clause of the MIB.
 *                 See RFC 1903 Section 3.1 for details. may be NULL.
 * @param units    Contents of the UNITS clause of the MIB. may be NULL.
 *
 * @return 1 on success, or 0 on failure (out of memory, or buffer to
 *         small when not allowed to realloc.)
 */
int
sprint_realloc_timeticks(u_char ** buf, size_t * buf_len, size_t * out_len,
                         int allow_realloc,
                         const netsnmp_variable_list * var,
                         const struct enum_list *enums,
                         const char *hint, const char *units)
{
    char            timebuf[40];

    if (var->type != ASN_TIMETICKS) {
        if (!netsnmp_ds_get_boolean(
                NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT)) {
            u_char          str[] = "Wrong Type (should be Timeticks): ";
            if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str))
                return 0;
        }
        return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, var, NULL, NULL,
                                          NULL);
    }

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS)) {
        char            str[32];
        snprintf(str, sizeof(str), "%lu", *(u_long *) var->val.integer);
        if (!snmp_strcat
            (buf, buf_len, out_len, allow_realloc, (const u_char *) str)) {
            return 0;
        }
        return 1;
    }
    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT)) {
        char            str[32];
        snprintf(str, sizeof(str), "Timeticks: (%lu) ",
                 *(u_long *) var->val.integer);
        if (!snmp_strcat
            (buf, buf_len, out_len, allow_realloc, (const u_char *) str)) {
            return 0;
        }
    }
    uptimeString(*(u_long *) (var->val.integer), timebuf, sizeof(timebuf));
    if (!snmp_strcat
        (buf, buf_len, out_len, allow_realloc, (const u_char *) timebuf)) {
        return 0;
    }
    if (units) {
        return (snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) " ")
                && snmp_strcat(buf, buf_len, out_len, allow_realloc,
                               (const u_char *) units));
    }
    return 1;
}


/**
 * Set's the printing function printomat in a subtree according
 * it's type
 *
 * @param subtree    The subtree to set.
 */
void
set_function(struct tree *subtree)
{
    subtree->printer = NULL;
    switch (subtree->type) {
    case TYPE_OBJID:
        subtree->printomat = sprint_realloc_object_identifier;
        break;
    case TYPE_OCTETSTR:
        subtree->printomat = sprint_realloc_octet_string;
        break;
    case TYPE_INTEGER:
        subtree->printomat = sprint_realloc_integer;
        break;
    case TYPE_INTEGER32:
        subtree->printomat = sprint_realloc_integer;
        break;
    /*case TYPE_NETADDR:
        subtree->printomat = sprint_realloc_networkaddress;
        break;
    case TYPE_IPADDR:
        subtree->printomat = sprint_realloc_ipaddress;
        break;
    case TYPE_COUNTER:
        subtree->printomat = sprint_realloc_counter;
        break;
    case TYPE_GAUGE:
        subtree->printomat = sprint_realloc_gauge;
        break;*/
    case TYPE_TIMETICKS:
        subtree->printomat = sprint_realloc_timeticks;
        break;
    /*
    case TYPE_NULL:
        subtree->printomat = sprint_realloc_null;
        break;
    case TYPE_BITSTRING:
        subtree->printomat = sprint_realloc_bitstring;
        break;
    case TYPE_NSAPADDRESS:
        subtree->printomat = sprint_realloc_nsapaddress;
        break;
    case TYPE_COUNTER64:
        subtree->printomat = sprint_realloc_counter64;
        break;
    case TYPE_UINTEGER:
        subtree->printomat = sprint_realloc_uinteger;
        break;
    case TYPE_UNSIGNED32:
        subtree->printomat = sprint_realloc_gauge;
        break;
    case TYPE_OTHER:
    default:
        subtree->printomat = sprint_realloc_by_type;
        break;*/
    }
}

static void
init_tree_roots(void)
{
    struct tree    *tp, *lasttp;
    int             base_modid;
    int             hash;

    base_modid = which_module("SNMPv2-SMI");
    if (base_modid == -1)
        base_modid = which_module("RFC1155-SMI");
    if (base_modid == -1)
        base_modid = which_module("RFC1213-MIB");

    /*
     * build root node
     */
    tp = (struct tree *) calloc(1, sizeof(struct tree));
    if (tp == NULL){
        return;
    }
    tp->label = strdup("joint-iso-ccitt");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 2;
    tp->tc_index = -1;
    set_function(tp);           /* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[0].label = strdup(tp->label);
    root_imports[0].modid = base_modid;

    /*
     * build root node
     */
    tp = (struct tree *) calloc(1, sizeof(struct tree));
    if (tp == NULL)
        return;
    tp->next_peer = lasttp;
    tp->label = strdup("ccitt");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 0;
    tp->tc_index = -1;
    set_function(tp);           /* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[1].label = strdup(tp->label);
    root_imports[1].modid = base_modid;

    /*
     * build root node
     */
    tp = (struct tree *) calloc(1, sizeof(struct tree));
    if (tp == NULL)
        return;
    tp->next_peer = lasttp;
    tp->label = strdup("iso");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 1;
    tp->tc_index = -1;
    set_function(tp);           /* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[2].label = strdup(tp->label);
    root_imports[2].modid = base_modid;

    tree_head = tp;
}

void
netsnmp_init_mib_internals(void)
{
    struct tok *tp;
    int    b, i;
    int             max_modc;

    if (tree_head){
        return;
    }

    /*
     * Set up hash list of pre-defined tokens
     */
    memset(buckets, 0, sizeof(buckets));
    for (tp = tokens; tp->name; tp++) {
        tp->hash = name_hash(tp->name);
        b = BUCKET(tp->hash);
        if (buckets[b])
            tp->next = buckets[b];
        buckets[b] = tp;
    }

    /*
     * Initialise other internal structures
     */

    max_modc = sizeof(module_map) / sizeof(module_map[0]) - 1;
    for (i = 0; i < max_modc; ++i)
        module_map[i].next = &(module_map[i + 1]);
    module_map[max_modc].next = NULL;
    module_map_head = module_map;

    memset(nbuckets, 0, sizeof(nbuckets));
    memset(tbuckets, 0, sizeof(tbuckets));
    tc_alloc = TC_INCR;
    tclist = (struct tc*) calloc(tc_alloc, sizeof(struct tc));
    build_translation_table();
    init_tree_roots();          /* Set up initial roots */
}

void
print_subtree(FILE * f, struct tree *tree, int count)
{
    struct tree    *tp;
    int             i;
    char            modbuf[256];

    for (i = 0; i < count; i++)
        fprintf(f, "  ");
    fprintf(f, "Children of %s(%ld):\n", tree->label, tree->subid);
    count++;
    for (tp = tree->child_list; tp; tp = tp->next_peer) {
        for (i = 0; i < count; i++)
            fprintf(f, "  ");
        fprintf(f, "%s:%s(%ld) type=%d",
                module_name(tp->module_list[0], modbuf),
                tp->label, tp->subid, tp->type);
        if (tp->tc_index != -1)
            fprintf(f, " tc=%d", tp->tc_index);
        if (tp->hint)
            fprintf(f, " hint=%s", tp->hint);
        if (tp->units)
            fprintf(f, " units=%s", tp->units);
        if (tp->number_modules > 1) {
            fprintf(f, " modules:");
            for (i = 1; i < tp->number_modules; i++)
                fprintf(f, " %s", module_name(tp->module_list[i], modbuf));
        }
        fprintf(f, "\n");
    }
    for (tp = tree->child_list; tp; tp = tp->next_peer) {
        if (tp->child_list)
            print_subtree(f, tp, count);
    }
}

/**
 * Read a single character from a file. Assumes that the caller has invoked
 * flockfile(). Uses fgetc_unlocked() instead of getc() since the former is
 * implemented as an inline function in glibc. See also bug 3447196
 * (http://sourceforge.net/tracker/?func=detail&aid=3447196&group_id=12694&atid=112694).
 */
static int netsnmp_getc(FILE *stream)
{
    return getc(stream);
}

static int
parseQuoteString(FILE * fp, char *token, int maxtlen)
{
    int    ch;
    int             count = 0;
    int             too_long = 0;
    char           *token_start = token;

    for (ch = netsnmp_getc(fp); ch != EOF; ch = netsnmp_getc(fp)) {
        if (ch == '\r')
            continue;
        if (ch == '\n') {
            mibLine++;
        } else if (ch == '"') {
            *token = '\0';
            if (too_long && netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                                           NETSNMP_DS_LIB_MIB_WARNINGS) > 1) {
                /*
                 * show short form for brevity sake
                 */
                char            ch_save = *(token_start + 50);
                *(token_start + 50) = '\0';
                *(token_start + 50) = ch_save;
            }
            return QUOTESTRING;
        }
        /*
         * maximum description length check.  If greater, keep parsing
         * but truncate the string
         */
        if (++count < maxtlen)
            *token++ = ch;
        else
            too_long = 1;
    }

    return 0;
}

/*
 * return zero if character is not a label character.
 */
static int
is_labelchar(int ich)
{
    if ((isalnum(ich)) || (ich == '-'))
        return 1;
    if (ich == '_' && netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                             NETSNMP_DS_LIB_MIB_PARSE_LABEL)) {
        return 1;
    }

    return 0;
}

/*
 * Parses a token from the file.  The type of the token parsed is returned,
 * and the text is placed in the string pointed to by token.
 * Warning: this method may recurse.
 */
static int
get_token(FILE * fp, char *token, int maxtlen)
{
    int    ch, ch_next;
    char  *cp = token;
    int    hash = 0;
    struct tok *tp;
    int             too_long = 0;
    enum { bdigits, xdigits, other } seenSymbols;

    /*
     * skip all white space
     */
    do {
        ch = netsnmp_getc(fp);
        if (ch == '\n')
            mibLine++;
    }
    while (isspace(ch) && ch != EOF);
    *cp++ = ch;
    *cp = '\0';
    switch (ch) {
    case EOF:
        return ENDOFFILE;
    case '"':
        return parseQuoteString(fp, token, maxtlen);
    case '\'':                 /* binary or hex constant */
        seenSymbols = bdigits;
        while ((ch = netsnmp_getc(fp)) != EOF && ch != '\'') {
            switch (seenSymbols) {
            case bdigits:
                if (ch == '0' || ch == '1')
                    break;
                seenSymbols = xdigits;
                /* FALL THROUGH */
            case xdigits:
                if (isxdigit(ch))
                    break;
                seenSymbols = other;
            case other:
                break;
            }
            if (cp - token < maxtlen - 2)
                *cp++ = ch;
        }
        if (ch == '\'') {
            unsigned long   val = 0;
            char           *run = token + 1;
            ch = netsnmp_getc(fp);
            switch (ch) {
            case EOF:
                return ENDOFFILE;
            case 'b':
            case 'B':
                if (seenSymbols > bdigits) {
                    *cp++ = '\'';
                    *cp = 0;
                    return LABEL;
                }
                while (run != cp)
                    val = val * 2 + *run++ - '0';
                break;
            case 'h':
            case 'H':
                if (seenSymbols > xdigits) {
                    *cp++ = '\'';
                    *cp = 0;
                    return LABEL;
                }
                while (run != cp) {
                    ch = *run++;
                    if ('0' <= ch && ch <= '9')
                        val = val * 16 + ch - '0';
                    else if ('a' <= ch && ch <= 'f')
                        val = val * 16 + ch - 'a' + 10;
                    else if ('A' <= ch && ch <= 'F')
                        val = val * 16 + ch - 'A' + 10;
                }
                break;
            default:
                *cp++ = '\'';
                *cp = 0;
                return LABEL;
            }
            sprintf(token, "%ld", val);
            return NUMBER;
        } else
            return LABEL;
    case '(':
        return LEFTPAREN;
    case ')':
        return RIGHTPAREN;
    case '{':
        return LEFTBRACKET;
    case '}':
        return RIGHTBRACKET;
    case '[':
        return LEFTSQBRACK;
    case ']':
        return RIGHTSQBRACK;
    case ';':
        return SEMI;
    case ',':
        return COMMA;
    case '|':
        return BAR;
    case '.':
        ch_next = netsnmp_getc(fp);
        if (ch_next == '.')
            return RANGE;
        ungetc(ch_next, fp);
        return LABEL;
    case ':':
        ch_next = netsnmp_getc(fp);
        if (ch_next != ':') {
            ungetc(ch_next, fp);
            return LABEL;
        }
        ch_next = netsnmp_getc(fp);
        if (ch_next != '=') {
            ungetc(ch_next, fp);
            return LABEL;
        }
        return EQUALS;
    case '-':
        ch_next = netsnmp_getc(fp);
        if (ch_next == '-') {
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                       NETSNMP_DS_LIB_MIB_COMMENT_TERM)) {
                /*
                 * Treat the rest of this line as a comment.
                 */
                while ((ch_next != EOF) && (ch_next != '\n'))
                    ch_next = netsnmp_getc(fp);
            } else {
                /*
                 * Treat the rest of the line or until another '--' as a comment
                 */
                /*
                 * (this is the "technically" correct way to parse comments)
                 */
                ch = ' ';
                ch_next = netsnmp_getc(fp);
                while (ch_next != EOF && ch_next != '\n' &&
                       (ch != '-' || ch_next != '-')) {
                    ch = ch_next;
                    ch_next = netsnmp_getc(fp);
                }
            }
            if (ch_next == EOF)
                return ENDOFFILE;
            if (ch_next == '\n')
                mibLine++;
            return get_token(fp, token, maxtlen);
        }
        ungetc(ch_next, fp);
        /* fallthrough */
    default:
        /*
         * Accumulate characters until end of token is found.  Then attempt to
         * match this token as a reserved word.  If a match is found, return the
         * type.  Else it is a label.
         */
        if (!is_labelchar(ch))
            return LABEL;
        hash += tolower(ch);
      more:
        while (is_labelchar(ch_next = netsnmp_getc(fp))) {
            hash += tolower(ch_next);
            if (cp - token < maxtlen - 1)
                *cp++ = ch_next;
            else
                too_long = 1;
        }
        ungetc(ch_next, fp);
        *cp = '\0';

        for (tp = buckets[BUCKET(hash)]; tp; tp = tp->next) {
            if ((tp->hash == hash) && (!strcmp(tp->name, token)))
                break;
        }
        if (tp) {
            if (tp->token != CONTINUE)
                return (tp->token);
            while (isspace((ch_next = netsnmp_getc(fp))))
                if (ch_next == '\n')
                    mibLine++;
            if (ch_next == EOF)
                return ENDOFFILE;
            if (isalnum(ch_next)) {
                *cp++ = ch_next;
                hash += tolower(ch_next);
                goto more;
            }
        }
        if (token[0] == '-' || isdigit((unsigned char)(token[0]))) {
            for (cp = token + 1; *cp; cp++)
                if (!isdigit((unsigned char)(*cp)))
                    return LABEL;
            return NUMBER;
        }
        return LABEL;
    }
}

static void
new_module(const char *name, const char *file)
{
    struct module  *mp;

    for (mp = module_head; mp; mp = mp->next)
        if (!strcmp(mp->name, name)) {
            /*
             * Not the same file
             */
            if (strcmp(mp->file, file)) {
                /*
                 * Use the new one in preference
                 */
                free(mp->file);
                mp->file = strdup(file);
            }
            return;
        }

    /*
     * Add this module to the list
     */
    mp = (struct module *) calloc(1, sizeof(struct module));
    if (mp == NULL)
        return;
    mp->name = strdup(name);
    mp->file = strdup(file);
    mp->imports = NULL;
    mp->no_imports = -1;        /* Not yet loaded */
    mp->modid = max_module;
    ++max_module;

    mp->next = module_head;     /* Or add to the *end* of the list? */
    module_head = mp;
}

int
add_mibfile(const char* tmpstr)
{
    FILE           *fp;
    char            token[MAXTOKEN], token2[MAXTOKEN];

    /*
     * which module is this
     */
    if ((fp = fopen(tmpstr, "r")) == NULL) {
        return 1;
    }
    std::string s(tmpstr);
    mibLine = 1;
    File = tmpstr;
    if (get_token(fp, token, MAXTOKEN) != LABEL) {
            fclose(fp);
            return 1;
    }
    /*
     * simple test for this being a MIB
     */
    if (get_token(fp, token2, MAXTOKEN) == DEFINITIONS) {
        new_module(token, tmpstr);
        fclose(fp);
        return 0;
    } else {
        fclose(fp);
        return 1;
    }
}

static int elemcmp(const void *a, const void *b)
{
    char* s1, * s2;
    s1 = (char*) a;
    s2 = (char*) b;
    return strcmp(s1, s2);
}

/*
 * Scan a directory and return all filenames found as an array of pointers to
 * directory entries (@result).
 */
static int scan_directory(char ***result, const char *dirname)
{
    DIR            *dir, *dir2;
    struct dirent  *file;
    char          **filenames = NULL;
    int             fname_len, i, filename_count = 0, array_size = 0;
    char           *tmpstr;

    *result = NULL;

    dir = opendir(dirname);
    if (!dir)
        return -1;

    while ((file = readdir(dir))) {
        /*
         * Only parse file names that don't begin with a '.'
         * Also skip files ending in '~', or starting/ending
         * with '#' which are typically editor backup files.
         */
        fname_len = strlen(file->d_name);
        if (fname_len > 0 && file->d_name[0] != '.'
            && file->d_name[0] != '#'
            && file->d_name[fname_len-1] != '#'
            && file->d_name[fname_len-1] != '~') {
            if (asprintf(&tmpstr, "%s/%s", dirname, file->d_name) < 0)
                continue;
            dir2 = opendir(tmpstr);
            if (dir2) {
                /* file is a directory, don't read it */
                closedir(dir2);
            } else {
                if (filename_count >= array_size) {
                    char **new_filenames;

                    array_size = (array_size + 16) * 2;
                    new_filenames = (char**) realloc(filenames,
                                        array_size * sizeof(filenames[0]));
                    if (!new_filenames) {
                        free(tmpstr);
                        for (i = 0; i < filename_count; i++)
                            free(filenames[i]);
                        free(filenames);
                        closedir(dir);
                        return -1;
                    }
                    filenames = new_filenames;
                }
                filenames[filename_count++] = tmpstr;
                tmpstr = NULL;
            }
            free(tmpstr);
        }
    }
    closedir(dir);

    if (filenames)
        qsort(filenames, filename_count, sizeof(filenames[0]), elemcmp);
    *result = filenames;

    return filename_count;
}


int
add_mibdir(const char *dirname)
{
    const char     *oldFile = File;
    char          **filenames;
    int             count = 0;
    int             filename_count, i;

    filename_count = scan_directory(&filenames, dirname);

    if (filename_count >= 0) {
        for (i = 0; i < filename_count; i++) {
            if (add_mibfile(filenames[i]) == 0)
                count++;
        free(filenames[i]);
        }
        File = oldFile;
        free(filenames);
        return (count);
    }
    else
        std::cout << "parse-mibs cannot open MIB directory" << std::endl;

    return (-1);
}

static void
init_node_hash(struct node *nodes)
{
    struct node    *np, *nextp;
    int             hash;

    memset(nbuckets, 0, sizeof(nbuckets));
    for (np = nodes; np;) {
        nextp = np->next;
        hash = NBUCKET(name_hash(np->parent));
        np->next = nbuckets[hash];
        nbuckets[hash] = np;
        np = nextp;
    }
}

/*
 * return index into tclist of given TC descriptor
 * return -1 if not found
 */
static int
get_tc_index(const char *descriptor, int modid)
{
    int             i;
    struct tc      *tcp;
    struct module  *mp;
    struct module_import *mip;

    /*
     * Check that the descriptor isn't imported
     *  by searching the import list
     */

    for (mp = module_head; mp; mp = mp->next)
        if (mp->modid == modid)
            break;
    if (mp)
        for (i = 0, mip = mp->imports; i < mp->no_imports; ++i, ++mip) {
            if (!strcmp(mip->label, descriptor)) {
                /*
                 * Found it - so amend the module ID
                 */
                modid = mip->modid;
                break;
            }
        }


    for (i = 0, tcp = tclist; i < tc_alloc; i++, tcp++) {
        if (tcp->type == 0)
            break;
        if (!strcmp(descriptor, tcp->descriptor) &&
            ((modid == tcp->modid) || (modid == -1))) {
            return i;
        }
    }
    return -1;
}

static void
free_enums(struct enum_list **spp)
{
    if (spp && *spp) {
        struct enum_list *pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->label)
                free(pp->label);
            free(pp);
            pp = npp;
        }
    }
}

static void
free_ranges(struct range_list **spp)
{
    if (spp && *spp) {
        struct range_list *pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            free(pp);
            pp = npp;
        }
    }
}

static void
free_indexes(struct index_list **spp)
{
    if (spp && *spp) {
        struct index_list *pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->ilabel)
                free(pp->ilabel);
            free(pp);
            pp = npp;
        }
    }
}

static void
free_varbinds(struct varbind_list **spp)
{
    if (spp && *spp) {
        struct varbind_list *pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->vblabel)
                free(pp->vblabel);
            free(pp);
            pp = npp;
        }
    }
}

static void
free_partial_tree(struct tree *tp, int keep_label)
{
    if (!tp)
        return;

    /*
     * remove the data from this tree node
     */
    free_enums(&tp->enums);
    free_ranges(&tp->ranges);
    free_indexes(&tp->indexes);
    free_varbinds(&tp->varbinds);
    if (!keep_label)
        SNMP_FREE(tp->label);
    SNMP_FREE(tp->hint);
    SNMP_FREE(tp->units);
    SNMP_FREE(tp->description);
    SNMP_FREE(tp->reference);
    SNMP_FREE(tp->augments);
    SNMP_FREE(tp->defaultValue);
}

/*
 * transfer data to tree from node
 *
 * move pointers for alloc'd data from np to tp.
 * this prevents them from being freed when np is released.
 * parent member is not moved.
 *
 * CAUTION: nodes may be repeats of existing tree nodes.
 * This can happen especially when resolving IMPORT clauses.
 *
 */
static void
tree_from_node(struct tree *tp, struct node *np)
{
    free_partial_tree(tp, FALSE);

    tp->label = np->label;
    np->label = NULL;
    tp->enums = np->enums;
    np->enums = NULL;
    tp->ranges = np->ranges;
    np->ranges = NULL;
    tp->indexes = np->indexes;
    np->indexes = NULL;
    tp->augments = np->augments;
    np->augments = NULL;
    tp->varbinds = np->varbinds;
    np->varbinds = NULL;
    tp->hint = np->hint;
    np->hint = NULL;
    tp->units = np->units;
    np->units = NULL;
    tp->description = np->description;
    np->description = NULL;
    tp->reference = np->reference;
    np->reference = NULL;
    tp->defaultValue = np->defaultValue;
    np->defaultValue = NULL;
    tp->subid = np->subid;
    tp->tc_index = np->tc_index;
    tp->type = translation_table[np->type];
    tp->access = np->access;
    tp->status = np->status;

    set_function(tp);
}

static void
unlink_tbucket(struct tree *tp)
{
    int             hash = NBUCKET(name_hash(tp->label));
    struct tree    *otp = NULL, *ntp = tbuckets[hash];

    while (ntp && ntp != tp) {
        otp = ntp;
        ntp = ntp->next;
    }
    if (!ntp)
        return;
    else if (otp)
        otp->next = ntp->next;
    else
        tbuckets[hash] = tp->next;
}

/*
 * free a tree node. Note: the node must already have been unlinked
 * from the tree when calling this routine
 */
static void
free_tree(struct tree *Tree)
{
    if (!Tree)
        return;

    unlink_tbucket(Tree);
    free_partial_tree(Tree, FALSE);
    if (Tree->module_list != &Tree->modid)
        free(Tree->module_list);
    free(Tree);
}

static void
free_node(struct node *np)
{
    if (!np)
        return;

    free_enums(&np->enums);
    free_ranges(&np->ranges);
    free_indexes(&np->indexes);
    free_varbinds(&np->varbinds);
    free(np->label);
    free(np->hint);
    free(np->units);
    free(np->description);
    free(np->reference);
    free(np->defaultValue);
    free(np->parent);
    free(np->augments);
    free(np->filename);
    free(np);
}

static void
merge_anon_children(struct tree *tp1, struct tree *tp2)
                /*
                 * NB: tp1 is the 'anonymous' node
                 */
{
    struct tree    *child1, *child2, *previous;

    for (child1 = tp1->child_list; child1;) {

        for (child2 = tp2->child_list, previous = NULL;
             child2; previous = child2, child2 = child2->next_peer) {

            if (child1->subid == child2->subid) {
                /*
                 * Found 'matching' children,
                 *  so merge them
                 */
                if (!strncmp(child1->label, ANON, ANON_LEN)) {
                    merge_anon_children(child1, child2);

                    child1->child_list = NULL;
                    previous = child1;  /* Finished with 'child1' */
                    child1 = child1->next_peer;
                    free_tree(previous);
                    goto next;
                }

                else if (!strncmp(child2->label, ANON, ANON_LEN)) {
                    merge_anon_children(child2, child1);

                    if (previous)
                        previous->next_peer = child2->next_peer;
                    else
                        tp2->child_list = child2->next_peer;
                    free_tree(child2);

                    previous = child1;  /* Move 'child1' to 'tp2' */
                    child1 = child1->next_peer;
                    previous->next_peer = tp2->child_list;
                    tp2->child_list = previous;
                    for (previous = tp2->child_list;
                         previous; previous = previous->next_peer)
                        previous->parent = tp2;
                    goto next;
                } else if (!strcmp(child1->label, child2->label)) {
                    continue;
                } else {
                    /*
                     * Two copies of the same node.
                     * 'child2' adopts the children of 'child1'
                     */

                    if (child2->child_list) {
                        for (previous = child2->child_list; previous->next_peer; previous = previous->next_peer);       /* Find the end of the list */
                        previous->next_peer = child1->child_list;
                    } else
                        child2->child_list = child1->child_list;
                    for (previous = child1->child_list;
                         previous; previous = previous->next_peer)
                        previous->parent = child2;
                    child1->child_list = NULL;

                    previous = child1;  /* Finished with 'child1' */
                    child1 = child1->next_peer;
                    free_tree(previous);
                    goto next;
                }
            }
        }
        /*
         * If no match, move 'child1' to 'tp2' child_list
         */
        if (child1) {
            previous = child1;
            child1 = child1->next_peer;
            previous->parent = tp2;
            previous->next_peer = tp2->child_list;
            tp2->child_list = previous;
        }
      next:;
    }
}

static void
unlink_tree(struct tree *tp)
{
    struct tree    *otp = NULL, *ntp = tp->parent;

    if (!ntp) {                 /* this tree has no parent */
        return;
    } else {
        ntp = ntp->child_list;

        while (ntp && ntp != tp) {
            otp = ntp;
            ntp = ntp->next_peer;
        }
        if (!ntp)
            return;
        else if (otp)
            otp->next_peer = ntp->next_peer;
        else
            tp->parent->child_list = tp->next_peer;
    }

    if (tree_head == tp)
        tree_head = tp->next_peer;
}

/*
 * Find all the children of root in the list of nodes.  Link them into the
 * tree and out of the nodes list.
 */
static void
do_subtree(struct tree *root, struct node **nodes)
{
    struct tree    *tp, *anon_tp = NULL;
    struct tree    *xroot = root;
    struct node    *np, **headp;
    struct node    *oldnp = NULL, *child_list = NULL, *childp = NULL;
    int             hash;
    int            *int_p;

    while (xroot->next_peer && xroot->next_peer->subid == root->subid) {
        xroot = xroot->next_peer;
    }

    tp = root;
    headp = &nbuckets[NBUCKET(name_hash(tp->label))];
    /*
     * Search each of the nodes for one whose parent is root, and
     * move each into a separate list.
     */
    for (np = *headp; np; np = np->next) {
        if (!strcmp(tp->label, np->parent)) {
            /*
             * take this node out of the node list
             */
            if (oldnp == NULL) {
                *headp = np->next;      /* fix root of node list */
            } else {
                oldnp->next = np->next; /* link around this node */
            }
            if (child_list)
                childp->next = np;
            else
                child_list = np;
            childp = np;
        } else {
            oldnp = np;
        }

    }
    if (childp)
        childp->next = NULL;
    /*
     * Take each element in the child list and place it into the tree.
     */
    for (np = child_list; np; np = np->next) {
        struct tree    *otp = NULL;
        struct tree    *xxroot = xroot;
        anon_tp = NULL;
        tp = xroot->child_list;

        if (np->subid == -1) {
            /*
             * name ::= { parent }
             */
            np->subid = xroot->subid;
            tp = xroot;
            xxroot = xroot->parent;
        }

        while (tp) {
            if (tp->subid == np->subid)
                break;
            else {
                otp = tp;
                tp = tp->next_peer;
            }
        }
        if (tp) {
            if (!strcmp(tp->label, np->label)) {
                /*
                 * Update list of modules
                 */
                int_p = (int*) malloc((tp->number_modules + 1) * sizeof(int));
                if (int_p == NULL)
                    return;
                memcpy(int_p, tp->module_list,
                       tp->number_modules * sizeof(int));
                int_p[tp->number_modules] = np->modid;
                if (tp->module_list != &tp->modid)
                    free(tp->module_list);
                ++tp->number_modules;
                tp->module_list = int_p;

                if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_MIB_REPLACE)) {
                    /*
                     * Replace from node
                     */
                    tree_from_node(tp, np);
                }
                /*
                 * Handle children
                 */
                do_subtree(tp, nodes);
                continue;
            }
            if (!strncmp(np->label, ANON, ANON_LEN) ||
                !strncmp(tp->label, ANON, ANON_LEN)) {
                anon_tp = tp;   /* Need to merge these two trees later */
            }
        }


        tp = (struct tree *) calloc(1, sizeof(struct tree));
        if (tp == NULL)
            return;
        tp->parent = xxroot;
        tp->modid = np->modid;
        tp->number_modules = 1;
        tp->module_list = &(tp->modid);
        tree_from_node(tp, np);
        if (!otp && !xxroot) {
          free(tp);
          return;
        }
        tp->next_peer = otp ? otp->next_peer : xxroot->child_list;
        if (otp)
            otp->next_peer = tp;
        else
            xxroot->child_list = tp;
        hash = NBUCKET(name_hash(tp->label));
        tp->next = tbuckets[hash];
        tbuckets[hash] = tp;
        do_subtree(tp, nodes);

        if (anon_tp) {
            if (!strncmp(tp->label, ANON, ANON_LEN)) {
                /*
                 * The new node is anonymous,
                 *  so merge it with the existing one.
                 */
                merge_anon_children(tp, anon_tp);

                /*
                 * unlink and destroy tp
                 */
                unlink_tree(tp);
                free_tree(tp);
            } else if (!strncmp(anon_tp->label, ANON, ANON_LEN)) {
                struct tree    *ntp;
                /*
                 * The old node was anonymous,
                 *  so merge it with the existing one,
                 *  and fill in the full information.
                 */
                merge_anon_children(anon_tp, tp);

                /*
                 * unlink anon_tp from the hash
                 */
                unlink_tbucket(anon_tp);

                /*
                 * get rid of old contents of anon_tp
                 */
                free_partial_tree(anon_tp, FALSE);

                /*
                 * put in the current information
                 */
                anon_tp->label = tp->label;
                anon_tp->child_list = tp->child_list;
                anon_tp->modid = tp->modid;
                anon_tp->tc_index = tp->tc_index;
                anon_tp->type = tp->type;
                anon_tp->enums = tp->enums;
                anon_tp->indexes = tp->indexes;
                anon_tp->augments = tp->augments;
                anon_tp->varbinds = tp->varbinds;
                anon_tp->ranges = tp->ranges;
                anon_tp->hint = tp->hint;
                anon_tp->units = tp->units;
                anon_tp->description = tp->description;
                anon_tp->reference = tp->reference;
                anon_tp->defaultValue = tp->defaultValue;
                anon_tp->parent = tp->parent;

                set_function(anon_tp);

                /*
                 * update parent pointer in moved children
                 */
                ntp = anon_tp->child_list;
                while (ntp) {
                    ntp->parent = anon_tp;
                    ntp = ntp->next_peer;
                }

                /*
                 * hash in anon_tp in its new place
                 */
                hash = NBUCKET(name_hash(anon_tp->label));
                anon_tp->next = tbuckets[hash];
                tbuckets[hash] = anon_tp;

                /*
                 * unlink and destroy tp
                 */
                unlink_tbucket(tp);
                unlink_tree(tp);
                free(tp);
            }
            anon_tp = NULL;
        }
    }
    /*
     * free all nodes that were copied into tree
     */
    oldnp = NULL;
    for (np = child_list; np; np = np->next) {
        if (oldnp)
            free_node(oldnp);
        oldnp = np;
    }
    if (oldnp)
        free_node(oldnp);
}

static void
do_linkup(struct module *mp, struct node *np)
{
    struct module_import *mip;
    struct node    *onp, *oldp, *newp;
    struct tree    *tp;
    int             i, more;
    /*
     * All modules implicitly import
     *   the roots of the tree
     */

    if (mp->no_imports == 0) {
        mp->no_imports = NUMBER_OF_ROOT_NODES;
        mp->imports = root_imports;
    }

    /*
     * Build the tree
     */
    init_node_hash(np);
    for (i = 0, mip = mp->imports; i < mp->no_imports; ++i, ++mip) {
        if (get_tc_index(mip->label, mip->modid) != -1)
            continue;
        tp = find_tree_node(mip->label, mip->modid);
        if (!tp) {
            continue;
        }
        do_subtree(tp, &np);
    }

    /*
     * If any nodes left over,
     *   check that they're not the result of a "fully qualified"
     *   name, and then add them to the list of orphans
     */

    if (!np){
        return;}



    for (tp = tree_head; tp; tp = tp->next_peer){
        do_subtree(tp, &np);
    }
    if (!np)
        return;

    /*
     * quietly move all internal references to the orphan list
     */
    oldp = orphan_nodes;
    do {
        for (i = 0; i < NHASHSIZE; i++)
            for (onp = nbuckets[i]; onp; onp = onp->next) {
                struct node    *op = NULL;
                int             hash = NBUCKET(name_hash(onp->label));
                np = nbuckets[hash];
                while (np) {
                    if (strcmp(onp->label, np->parent)) {
                        op = np;
                        np = np->next;
                    } else {
                        if (op)
                            op->next = np->next;
                        else
                            nbuckets[hash] = np->next;
                        np->next = orphan_nodes;
                        orphan_nodes = np;
                        op = NULL;
                        np = nbuckets[hash];
                    }
                }
            }
        newp = orphan_nodes;
        more = 0;
        for (onp = orphan_nodes; onp != oldp; onp = onp->next) {
            struct node    *op = NULL;
            int             hash = NBUCKET(name_hash(onp->label));
            np = nbuckets[hash];
            while (np) {
                if (strcmp(onp->label, np->parent)) {
                    op = np;
                    np = np->next;
                } else {
                    if (op)
                        op->next = np->next;
                    else
                        nbuckets[hash] = np->next;
                    np->next = orphan_nodes;
                    orphan_nodes = np;
                    op = NULL;
                    np = nbuckets[hash];
                    more = 1;
                }
            }
        }
        oldp = newp;
    } while (more);

    /*
     * complain about left over nodes
     */
    for (np = orphan_nodes; np && np->next; np = np->next);     /* find the end of the orphan list */
    for (i = 0; i < NHASHSIZE; i++)
        if (nbuckets[i]) {
            if (orphan_nodes)
                onp = np->next = nbuckets[i];
            else
                onp = orphan_nodes = nbuckets[i];
            nbuckets[i] = NULL;
            while (onp) {
                np = onp;
                onp = onp->next;
            }
        }
    return;
}


static void
scan_objlist(struct node *root, struct module *mp, struct objgroup *list, const char *error)
{
    int             oLine = mibLine;

    while (list) {
        struct objgroup *gp = list;
        struct node    *np;
        list = list->next;
        np = root;
        while (np)
            if (strcmp(np->label, gp->name))
                np = np->next;
            else
                break;
        if (!np) {
        int i;
        struct module_import *mip;
        /* if not local, check if it was IMPORTed */
        for (i = 0, mip = mp->imports; i < mp->no_imports; i++, mip++)
        if (strcmp(mip->label, gp->name) == 0)
            break;
        if (i == mp->no_imports) {
        mibLine = gp->line;
        }
        }
        free(gp->name);
        free(gp);
    }
    mibLine = oLine;
}


/*
 *  Read in the named module
 *      Returns the root of the whole tree
 *      (by analogy with 'read_mib')
 */
static int
read_module_internal(const char *name)
{
    struct module  *mp;
    FILE           *fp;
    struct node    *np;

    netsnmp_init_mib_internals();

    for (mp = module_head; mp; mp = mp->next)
        if (!strcmp(mp->name, name)) {
            const char     *oldFile = File;
            int             oldLine = mibLine;
            int             oldModule = current_module;

            if (mp->no_imports != -1) {
                //DEBUGMSGTL(("parse-mibs", "Module %s already loaded\n",
                           // name));
                return MODULE_ALREADY_LOADED;
            }
            if ((fp = fopen(mp->file, "r")) == NULL) {
                int rval;
                if (errno == ENOTDIR || errno == ENOENT)
                    rval = MODULE_NOT_FOUND;
                else
                    rval = MODULE_LOAD_FAILED;
                //snmp_log_perror(mp->file);
                return rval;
            }

            mp->no_imports = 0; /* Note that we've read the file */
            File = mp->file;
            mibLine = 1;
            current_module = mp->modid;
            /*
             * Parse the file
             */
            np = parse(fp, NULL);
            fclose(fp);
            File = oldFile;
            mibLine = oldLine;
            current_module = oldModule;
            if ((np == NULL) && (gMibError == MODULE_SYNTAX_ERROR) )
                return MODULE_SYNTAX_ERROR;
            return MODULE_LOADED_OK;
        }

    return MODULE_NOT_FOUND;
}

struct tree    *
netsnmp_read_module(const char *name)
{
    int status = 0;
    status = read_module_internal(name);

    if (status == MODULE_NOT_FOUND) {
        read_module_replacements(name);
    } else if (status == MODULE_SYNTAX_ERROR) {
        gMibError = 0;
        gLoop = 1;

        strncat(gMibNames, " ", sizeof(gMibNames) - strlen(gMibNames) - 1);
        strncat(gMibNames, name, sizeof(gMibNames) - strlen(gMibNames) - 1);
    }
    return tree_head;
}


static int
read_module_replacements(const char *name)
{
    struct module_compatability *mcp;

    for (mcp = module_map_head; mcp; mcp = mcp->next) {
        if (!strcmp(mcp->old_module, name)) {
            (void) netsnmp_read_module(mcp->new_module);
            return 1;
        }
    }
    return 0;
}


static int
read_import_replacements(const char *old_module_name,
                         struct module_import *identifier)
{
    struct module_compatability *mcp;

    /*
     * Look for matches first
     */
    for (mcp = module_map_head; mcp; mcp = mcp->next) {
        if (!strcmp(mcp->old_module, old_module_name)) {

            if (                /* exact match */
                   (mcp->tag_len == 0 &&
                    (mcp->tag == NULL ||
                     !strcmp(mcp->tag, identifier->label))) ||
                   /*
                    * prefix match
                    */
                   (mcp->tag_len != 0 &&
                    !strncmp(mcp->tag, identifier->label, mcp->tag_len))
                ) {

                (void) netsnmp_read_module(mcp->new_module);
                identifier->modid = which_module(mcp->new_module);
                return 1;         /* finished! */
            }
        }
    }

    /*
     * If no exact match, load everything relevant
     */
    return read_module_replacements(old_module_name);
}

/*
 * Parses a module import clause
 *   loading any modules referenced
 */
static void
parse_imports(FILE * fp)
{
    int    type;
    char            token[MAXTOKEN];
#define MAX_IMPORTS	512
    struct module_import *import_list;
    int             this_module;
    struct module  *mp;

    int             import_count = 0;   /* Total number of imported descriptors */
    int             i = 0, old_i;       /* index of first import from each module */

    import_list = (struct module_import *) malloc(MAX_IMPORTS * sizeof(*import_list));

    type = get_token(fp, token, MAXTOKEN);

    /*
     * Parse the IMPORTS clause
     */
    while (type != SEMI && type != ENDOFFILE) {
        if (type == LABEL) {
            if (import_count == MAX_IMPORTS) {
                do {
                    type = get_token(fp, token, MAXTOKEN);
                } while (type != SEMI && type != ENDOFFILE);
                goto out;
            }
            import_list[import_count++].label = strdup(token);
        } else if (type == FROM) {
            type = get_token(fp, token, MAXTOKEN);
            if (import_count == i) {    /* All imports are handled internally */
                type = get_token(fp, token, MAXTOKEN);
                continue;
            }
            this_module = which_module(token);

            for (old_i = i; i < import_count; ++i)
                import_list[i].modid = this_module;

            /*
             * Recursively read any pre-requisite modules
             */
            if (read_module_internal(token) == MODULE_NOT_FOUND) {
        int found = 0;
                for (; old_i < import_count; ++old_i) {
                    found += read_import_replacements(token, &import_list[old_i]);
                }
            }
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    /* Initialize modid in case the module name was missing. */
    for (; i < import_count; ++i)
        import_list[i].modid = -1;

    /*
     * Save the import information
     *   in the global module table
     */
    for (mp = module_head; mp; mp = mp->next) {
        if (mp->modid == current_module) {
            if (import_count == 0)
                goto out;
            if (mp->imports && (mp->imports != root_imports)) {
                /*
                 * this can happen if all modules are in one source file.
                 */
                for (i = 0; i < mp->no_imports; ++i) {

                    free(mp->imports[i].label);
                }
                free(mp->imports);
            }
            mp->imports = (struct module_import *)
                calloc(import_count, sizeof(struct module_import));
            if (mp->imports == NULL)
                goto out;
            for (i = 0; i < import_count; ++i) {
                mp->imports[i].label = import_list[i].label;
                mp->imports[i].modid = import_list[i].modid;

            }
            mp->no_imports = import_count;
            goto out;
        }
    }

out:
    free(import_list);
    return;
}

static struct node *
alloc_node(int modid)
{
    struct node    *np;

    np = (struct node*) calloc(1, sizeof(struct node));
    if (!np)
        return NULL;

    np->tc_index = -1;
    np->modid = modid;
    np->filename = strdup(File);
    np->lineno = mibLine;

    return np;
}

/*
 * Parses a MACRO definition
 * Expect BEGIN, discard everything to end.
 * Returns 0 on error.
 */
static struct node *
parse_macro(FILE * fp, char *name)
{
    int    type;
    char            token[MAXTOKEN];
    struct node    *np;
    int             iLine = mibLine;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, sizeof(token));
    while (type != EQUALS && type != ENDOFFILE) {
        type = get_token(fp, token, sizeof(token));
    }
    if (type != EQUALS) {
        if (np)
            free_node(np);
        return NULL;
    }
    while (type != BEGIN && type != ENDOFFILE) {
        type = get_token(fp, token, sizeof(token));
    }
    if (type != BEGIN) {
        if (np)
            free_node(np);
        return NULL;
    }
    while (type != END && type != ENDOFFILE) {
        type = get_token(fp, token, sizeof(token));
    }
    if (type != END) {
        if (np)
            free_node(np);
        return NULL;
    }

    return np;
}

static struct enum_list *
copy_enums(struct enum_list *sp)
{
    struct enum_list *xp = NULL, **spp = &xp;

    while (sp) {
        *spp = (struct enum_list *) calloc(1, sizeof(struct enum_list));
        if (!*spp)
            break;
        (*spp)->label = strdup(sp->label);
        (*spp)->value = sp->value;
        spp = &(*spp)->next;
        sp = sp->next;
    }
    return (xp);
}

static struct range_list *
copy_ranges(struct range_list *sp)
{
    struct range_list *xp = NULL, **spp = &xp;

    while (sp) {
        *spp = (struct range_list *) calloc(1, sizeof(struct range_list));
        if (!*spp)
            break;
        (*spp)->low = sp->low;
        (*spp)->high = sp->high;
        spp = &(*spp)->next;
        sp = sp->next;
    }
    return (xp);
}

static int
get_tc(const char *descriptor,
       int modid,
       int *tc_index,
       struct enum_list **ep, struct range_list **rp, char **hint)
{
    int             i;
    struct tc      *tcp;

    i = get_tc_index(descriptor, modid);
    if (tc_index)
        *tc_index = i;
    if (i != -1) {
        tcp = &tclist[i];
        if (ep) {
            free_enums(ep);
            *ep = copy_enums(tcp->enums);
        }
        if (rp) {
            free_ranges(rp);
            *rp = copy_ranges(tcp->ranges);
        }
        if (hint) {
            if (*hint)
                free(*hint);
            *hint = (tcp->hint ? strdup(tcp->hint) : NULL);
        }
        return tcp->type;
    }
    return LABEL;
}

/*
 * Parses an enumeration list of the form:
 *        { label(value) label(value) ... }
 * The initial { has already been parsed.
 * Returns NULL on error.
 */

static struct enum_list *
parse_enumlist(FILE * fp, struct enum_list **retp)
{
    int    type;
    char            token[MAXTOKEN];
    struct enum_list *ep = NULL, **epp = &ep;

    free_enums(retp);

    while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE) {
        if (type == RIGHTBRACKET)
            break;
        /* some enums use "deprecated" to indicate a no longer value label */
        /* (EG: IP-MIB's IpAddressStatusTC) */
        if (type == LABEL || type == DEPRECATED) {
            /*
             * this is an enumerated label
             */
            *epp =
                (struct enum_list *) calloc(1, sizeof(struct enum_list));
            if (*epp == NULL)
                return (NULL);
            /*
             * a reasonable approximation for the length
             */
            (*epp)->label = strdup(token);
            type = get_token(fp, token, MAXTOKEN);
            if (type != LEFTPAREN) {
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != NUMBER) {
                return NULL;
            }
            (*epp)->value = strtol(token, NULL, 10);
            type = get_token(fp, token, MAXTOKEN);
            if (type != RIGHTPAREN) {
                return NULL;
            }
            epp = &(*epp)->next;
        }
    }
    if (type == ENDOFFILE) {
        return NULL;
    }
    *retp = ep;
    return ep;
}

static struct range_list *
parse_ranges(FILE * fp, struct range_list **retp)
{
    int             low, high;
    char            nexttoken[MAXTOKEN];
    int             nexttype;
    struct range_list *rp = NULL, **rpp = &rp;
    int             size = 0, taken = 1;

    free_ranges(retp);

    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    if (nexttype == SIZE) {
        size = 1;
        taken = 0;
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
    }

    do {
        if (!taken)
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        else
            taken = 0;
        high = low = strtoul(nexttoken, NULL, 10);
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
        if (nexttype == RANGE) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            errno = 0;
            high = strtoul(nexttoken, NULL, 10);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        *rpp = (struct range_list *) calloc(1, sizeof(struct range_list));
        if (*rpp == NULL)
            break;
        (*rpp)->low = low;
        (*rpp)->high = high;
        rpp = &(*rpp)->next;

    } while (nexttype == BAR);
    if (size && nexttype <= MAXTOKEN) {
        nexttype = get_token(fp, nexttoken, nexttype);
    }

    *retp = rp;
    return rp;
}

/*
 * struct index_list *
 * getIndexes(FILE *fp):
 *   This routine parses a string like  { blah blah blah } and returns a
 *   list of the strings enclosed within it.
 *
 */
static struct index_list *
getIndexes(FILE * fp, struct index_list **retp)
{
    int             type;
    char            token[MAXTOKEN];
    char            nextIsImplied = 0;

    struct index_list *mylist = NULL;
    struct index_list **mypp = &mylist;

    free_indexes(retp);

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET) {
        return NULL;
    }

    type = get_token(fp, token, MAXTOKEN);
    while (type != RIGHTBRACKET && type != ENDOFFILE) {
        if ((type == LABEL) || (type & SYNTAX_MASK)) {
            *mypp =
                (struct index_list *) calloc(1, sizeof(struct index_list));
            if (*mypp) {
                (*mypp)->ilabel = strdup(token);
                (*mypp)->isimplied = nextIsImplied;
                mypp = &(*mypp)->next;
                nextIsImplied = 0;
            }
        } else if (type == IMPLIED) {
            nextIsImplied = 1;
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    *retp = mylist;
    return mylist;
}

/*
 * This routine parses a string like  { blah blah blah } and returns OBJID if
 * it is well formed, and NULL if not.
 */
static int
tossObjectIdentifier(FILE * fp)
{
    int             type;
    char            token[MAXTOKEN];
    int             bracketcount = 1;

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET)
        return 0;
    while ((type != RIGHTBRACKET || bracketcount > 0) && type != ENDOFFILE) {
        type = get_token(fp, token, MAXTOKEN);
        if (type == LEFTBRACKET)
            bracketcount++;
        else if (type == RIGHTBRACKET)
            bracketcount--;
    }

    if (type == RIGHTBRACKET)
        return OBJID;
    else
        return 0;
}

/**
 * Read an OID from a file.
 * @param[in]  file   File to read from.
 * @param[out] id_arg Array to store the OID in.
 * @param[in]  length Number of elements in the @id_arg array.
 *
 * Takes a list of the form:
 * { iso org(3) dod(6) 1 }
 * and creates several nodes, one for each parent-child pair.
 * Returns 0 on error.
 */
static int
getoid(FILE * fp, struct subid_s *id_arg, int length)
{
    struct subid_s *id = id_arg;
    int             i, count, type;
    char            token[MAXTOKEN];

    if ((type = get_token(fp, token, MAXTOKEN)) != LEFTBRACKET) {
        return 0;
    }
    type = get_token(fp, token, MAXTOKEN);
    for (count = 0; count < length; count++, id++) {
        id->label = NULL;
        id->modid = current_module;
        id->subid = -1;
        if (type == RIGHTBRACKET)
            return count;
        if (type == LABEL) {
            /*
             * this entry has a label
             */
            id->label = strdup(token);
            type = get_token(fp, token, MAXTOKEN);
            if (type == LEFTPAREN) {
                type = get_token(fp, token, MAXTOKEN);
                if (type == NUMBER) {
                    id->subid = strtoul(token, NULL, 10);
                    if ((type =
                         get_token(fp, token, MAXTOKEN)) != RIGHTPAREN) {

                        goto free_labels;
                    }
                } else {

                    goto free_labels;
                }
            } else {
                continue;
            }
        } else if (type == NUMBER) {
            /*
             * this entry  has just an integer sub-identifier
             */
            id->subid = strtoul(token, NULL, 10);
        } else {

            goto free_labels;
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    --count;

free_labels:
    for (i = 0; i <= count; i++) {
        free(id_arg[i].label);
        id_arg[i].label = NULL;
    }

    return 0;
}

/*
 * Parse a sequence of object subidentifiers for the given name.
 * The "label OBJECT IDENTIFIER ::=" portion has already been parsed.
 *
 * The majority of cases take this form :
 * label OBJECT IDENTIFIER ::= { parent 2 }
 * where a parent label and a child subidentifier number are specified.
 *
 * Variations on the theme include cases where a number appears with
 * the parent, or intermediate subidentifiers are specified by label,
 * by number, or both.
 *
 * Here are some representative samples :
 * internet        OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }
 * mgmt            OBJECT IDENTIFIER ::= { internet 2 }
 * rptrInfoHealth  OBJECT IDENTIFIER ::= { snmpDot3RptrMgt 0 4 }
 *
 * Here is a very rare form :
 * iso             OBJECT IDENTIFIER ::= { 1 }
 *
 * Returns NULL on error.  When this happens, memory may be leaked.
 */
static struct node *
parse_objectid(FILE * fp, char *name)
{
    int    count;
    struct subid_s *op, *nop;
    int             length;
    struct subid_s  loid[32];
    struct node    *np, *root = NULL, *oldnp = NULL;
    struct tree    *tp;

    if ((length = getoid(fp, loid, 32)) == 0) {
        return NULL;
    }

    /*
     * Handle numeric-only object identifiers,
     *  by labelling the first sub-identifier
     */
    op = loid;
    if (!op->label) {
        if (length == 1) {
            return NULL;
        }
        for (tp = tree_head; tp; tp = tp->next_peer)
            if ((int) tp->subid == op->subid) {
                op->label = strdup(tp->label);
                break;
            }
    }

    /*
     * Handle  "label OBJECT-IDENTIFIER ::= { subid }"
     */
    if (length == 1) {
        op = loid;
        np = alloc_node(op->modid);
        if (np == NULL)
            return (NULL);
        np->subid = op->subid;
        np->label = strdup(name);
        np->parent = op->label;
        return np;
    }

    /*
     * For each parent-child subid pair in the subid array,
     * create a node and link it into the node list.
     */
    for (count = 0, op = loid, nop = loid + 1; count < (length - 1);
         count++, op++, nop++) {
        /*
         * every node must have parent's name and child's name or number
         */
        /*
         * XX the next statement is always true -- does it matter ??
         */
        if (op->label && (nop->label || (nop->subid != -1))) {
            np = alloc_node(nop->modid);
            if (np == NULL)
                goto err;
            if (root == NULL) {
                root = np;
            } else {
                oldnp->next = np;
            }
            oldnp = np;

            np->parent = strdup(op->label);
            if (count == (length - 2)) {
                /*
                 * The name for this node is the label for this entry
                 */
                np->label = strdup(name);
                if (np->label == NULL)
                    goto err;
            } else {
                if (!nop->label) {
                    if (asprintf(&nop->label, "%s%d", ANON, anonymous++) < 0)
                        goto err;
                }
                np->label = strdup(nop->label);
            }
            if (nop->subid != -1)
                np->subid = nop->subid;
        }                       /* end if(op->label... */
    }

out:
    /*
     * free the loid array
     */
    for (count = 0, op = loid; count < length; count++, op++) {
        free(op->label);
        op->label = NULL;
    }

    return root;

err:
    for (; root; root = np) {
        np = root->next;
        free_node(root);
    }
    goto out;
}

/*
 * Merge the parsed object identifier with the existing node.
 * If there is a problem with the identifier, release the existing node.
 */
static struct node *
merge_parse_objectid(struct node *np, FILE * fp, char *name)
{
    struct node    *nnp;
    /*
     * printf("merge defval --> %s\n",np->defaultValue);
     */
    nnp = parse_objectid(fp, name);
    if (nnp) {

        /*
         * apply last OID sub-identifier data to the information
         */
        /*
         * already collected for this node.
         */
        struct node    *headp, *nextp;
        int             ncount = 0;
        nextp = headp = nnp;
        while (nnp->next) {
            nextp = nnp;
            ncount++;
            nnp = nnp->next;
        }

        np->label = nnp->label;
        np->subid = nnp->subid;
        np->modid = nnp->modid;
        np->parent = nnp->parent;
    if (nnp->filename != NULL) {
      free(nnp->filename);
    }
        free(nnp);

        if (ncount) {
            nextp->next = np;
            np = headp;
        }
    } else {
        free_node(np);
        np = NULL;
    }

    return np;
}


/*
 * Parses an OBJECT TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_objecttype(FILE * fp, char *name)
{
    int    type;
    char            token[MAXTOKEN];
    char            nexttoken[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    int             nexttype, tctype;
    struct node *np;

    type = get_token(fp, token, MAXTOKEN);
    if (type != SYNTAX) {
        return NULL;
    }
    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type == OBJECT) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != IDENTIFIER) {
            free_node(np);
            return NULL;
        }
        type = OBJID;
    }
    if (type == LABEL) {
        int             tmp_index;
        tctype = get_tc(token, current_module, &tmp_index,
                        &np->enums, &np->ranges, &np->hint);
        type = tctype;
        np->tc_index = tmp_index;       /* store TC for later reference */
    }
    np->type = type;
    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    switch (type) {
    case SEQUENCE:
        if (nexttype == OF) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);

        }
        break;
    case INTEGER:
    case INTEGER32:
    case UINTEGER32:
    case UNSIGNED32:
    case COUNTER:
    case GAUGE:
    case BITSTRING:
    case LABEL:
        if (nexttype == LEFTBRACKET) {
            /*
             * if there is an enumeration list, parse it
             */
            np->enums = parse_enumlist(fp, &np->enums);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        } else if (nexttype == LEFTPAREN) {
            /*
             * if there is a range list, parse it
             */
            np->ranges = parse_ranges(fp, &np->ranges);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        break;
    case OCTETSTR:
    case KW_OPAQUE:
        /*
         * parse any SIZE specification
         */
        if (nexttype == LEFTPAREN) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            if (nexttype == SIZE) {
                nexttype = get_token(fp, nexttoken, MAXTOKEN);
                if (nexttype == LEFTPAREN) {
                    np->ranges = parse_ranges(fp, &np->ranges);
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);      /* ) */
                    if (nexttype == RIGHTPAREN) {
                        nexttype = get_token(fp, nexttoken, MAXTOKEN);
                        break;
                    }
                }
            }

            free_node(np);
            return NULL;
        }
        break;
    case OBJID:
    case NETADDR:
    case IPADDR:
    case TIMETICKS:
    case NUL:
    case NSAPADDRESS:
    case COUNTER64:
        break;
    default:

        free_node(np);
        return NULL;
    }
    if (nexttype == UNITS) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {

            free_node(np);
            return NULL;
        }
        np->units = strdup(quoted_string_buffer);
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
    }
    if (nexttype != ACCESS) {

        free_node(np);
        return NULL;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != READONLY && type != READWRITE && type != WRITEONLY
        && type != NOACCESS && type != READCREATE && type != ACCNOTIFY) {

        free_node(np);
        return NULL;
    }
    np->access = type;
    type = get_token(fp, token, MAXTOKEN);
    if (type != STATUS) {

        free_node(np);
        return NULL;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != MANDATORY && type != CURRENT && type != KW_OPTIONAL &&
        type != OBSOLETE && type != DEPRECATED) {

        free_node(np);
        return NULL;
    }
    np->status = type;
    /*
     * Optional parts of the OBJECT-TYPE macro
     */
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);

            if (type != QUOTESTRING) {

                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;

        case REFERENCE:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {

                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case INDEX:
            if (np->augments) {

                free_node(np);
                return NULL;
            }
            np->indexes = getIndexes(fp, &np->indexes);
            if (np->indexes == NULL) {

                free_node(np);
                return NULL;
            }
            break;
        case AUGMENTS:
            if (np->indexes) {

                free_node(np);
                return NULL;
            }
            np->indexes = getIndexes(fp, &np->indexes);
            if (np->indexes == NULL) {

                free_node(np);
                return NULL;
            }
            np->augments = strdup(np->indexes->ilabel);
            free_indexes(&np->indexes);
            break;
        case DEFVAL:
            /*
             * Mark's defVal section
             */
            type = get_token(fp, quoted_string_buffer, MAXTOKEN);
            if (type != LEFTBRACKET) {

                free_node(np);
                return NULL;
            }

            {
                int             level = 1;
                char            defbuf[512];

                defbuf[0] = 0;
                while (1) {
                    type = get_token(fp, quoted_string_buffer, MAXTOKEN);
                    if ((type == RIGHTBRACKET && --level == 0)
                        || type == ENDOFFILE)
                        break;
                    else if (type == LEFTBRACKET)
                        level++;
                    if (type == QUOTESTRING)
                        strlcat(defbuf, "\\\"", sizeof(defbuf));
                    strlcat(defbuf, quoted_string_buffer, sizeof(defbuf));
                    if (type == QUOTESTRING)
                        strlcat(defbuf, "\\\"", sizeof(defbuf));
                    strlcat(defbuf, " ", sizeof(defbuf));
                }

                if (type != RIGHTBRACKET) {

                    free_node(np);
                    return NULL;
                }

                /*
                 * Ensure strlen(defbuf) is above zero
                 */
                if (strlen(defbuf) == 0) {

                    free_node(np);
                    return NULL;
                }
                defbuf[strlen(defbuf) - 1] = 0;
                np->defaultValue = strdup(defbuf);
            }

            break;

        case NUM_ENTRIES:
            if (tossObjectIdentifier(fp) != OBJID) {

                free_node(np);
                return NULL;
            }
            break;

        default:

            free_node(np);
            return NULL;

        }
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != EQUALS) {

        free_node(np);
        return NULL;
    }
    return merge_parse_objectid(np, fp, name);
}

/*
 * Parses an OBJECT GROUP macro.
 * Returns 0 on error.
 *
 * Also parses object-identity, since they are similar (ignore STATUS).
 *   - WJH 10/96
 */
/*static struct node *
parse_objectgroup(FILE * fp, char *name, int what, struct objgroup **ol)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct node    *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type == what) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != LEFTBRACKET) {

            goto skip;
        }
        do {
            struct objgroup *o;
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {

                goto skip;
            }
            o = (struct objgroup *) malloc(sizeof(struct objgroup));
            if (!o) {

                goto skip;
            }
            o->line = mibLine;
            o->name = strdup(token);
            o->next = *ol;
            *ol = o;
            type = get_token(fp, token, MAXTOKEN);
        } while (type == COMMA);
        if (type != RIGHTBRACKET) {

            goto skip;
        }
        type = get_token(fp, token, type);
    }
    if (type != STATUS) {
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != DEPRECATED && type != OBSOLETE) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {

        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {

        free_node(np);
        return NULL;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {

            free_node(np);
            return NULL;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, MAXTOKEN);
    }
  skip:
    while (type != EQUALS && type != ENDOFFILE)
        type = get_token(fp, token, MAXTOKEN);

    return merge_parse_objectid(np, fp, name);
}*/

static struct varbind_list *
getVarbinds(FILE * fp, struct varbind_list **retp)
{
    int             type;
    char            token[MAXTOKEN];

    struct varbind_list *mylist = NULL;
    struct varbind_list **mypp = &mylist;

    free_varbinds(retp);

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET) {
        return NULL;
    }

    type = get_token(fp, token, MAXTOKEN);
    while (type != RIGHTBRACKET && type != ENDOFFILE) {
        if ((type == LABEL) || (type & SYNTAX_MASK)) {
            *mypp =
                (struct varbind_list *) calloc(1,
                                               sizeof(struct
                                                      varbind_list));
            if (*mypp) {
                (*mypp)->vblabel = strdup(token);
                mypp = &(*mypp)->next;
            }
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    *retp = mylist;
    return mylist;
}

/*
 * Parses an OBJECT GROUP macro.
 * Returns 0 on error.
 *
 * Also parses object-identity, since they are similar (ignore STATUS).
 *   - WJH 10/96
 */
static struct node *
parse_objectgroup(FILE * fp, char *name, int what, struct objgroup **ol)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct node    *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type == what) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != LEFTBRACKET) {
           // print_error("Expected \"{\"", token, type);
            goto skip;
        }
        do {
            struct objgroup *o;
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {
                //print_error("Bad identifier", token, type);
                goto skip;
            }
            o = (struct objgroup *) malloc(sizeof(struct objgroup));
            if (!o) {
                //print_error("Resource failure", token, type);
                goto skip;
            }
            o->line = mibLine;
            o->name = strdup(token);
            o->next = *ol;
            *ol = o;
            type = get_token(fp, token, MAXTOKEN);
        } while (type == COMMA);
        if (type != RIGHTBRACKET) {
            //print_error("Expected \"}\" after list", token, type);
            goto skip;
        }
        type = get_token(fp, token, type);
    }
    if (type != STATUS) {
        //print_error("Expected STATUS", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != DEPRECATED && type != OBSOLETE) {
        //print_error("Bad STATUS value", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {
        //print_error("Expected DESCRIPTION", token, type);
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {
        //print_error("Bad DESCRIPTION", quoted_string_buffer, type);
        free_node(np);
        return NULL;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {
            //print_error("Bad REFERENCE", quoted_string_buffer, type);
            free_node(np);
            return NULL;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != EQUALS)
        //print_error("Expected \"::=\"", token, type);
  skip:
    while (type != EQUALS && type != ENDOFFILE){
        type = get_token(fp, token, MAXTOKEN);
    }

    return merge_parse_objectid(np, fp, name);
}


/*
 * Parses a TRAP-TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_trapDefinition(FILE * fp, char *name)
{
     int    type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
     struct node *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {

                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;
        case REFERENCE:
            /* I'm not sure REFERENCEs are legal in smiv1 traps??? */
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {

                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case ENTERPRISE:
            type = get_token(fp, token, MAXTOKEN);
            if (type == LEFTBRACKET) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {

                    free_node(np);
                    return NULL;
                }
                np->parent = strdup(token);
                /*
                 * Get right bracket
                 */
                type = get_token(fp, token, MAXTOKEN);
            } else if (type == LABEL) {
                np->parent = strdup(token);
            } else {
                free_node(np);
                return NULL;
            }
            break;
        case VARIABLES:
            np->varbinds = getVarbinds(fp, &np->varbinds);
            if (!np->varbinds) {

                free_node(np);
                return NULL;
            }
            break;
        default:
            /*
             * NOTHING
             */
            break;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    type = get_token(fp, token, MAXTOKEN);

    np->label = strdup(name);

    if (type != NUMBER) {

        free_node(np);
        return NULL;
    }
    np->subid = strtoul(token, NULL, 10);
    np->next = alloc_node(current_module);
    if (np->next == NULL) {
        free_node(np);
        return (NULL);
    }

    /* Catch the syntax error */
    if (np->parent == NULL) {
        free_node(np->next);
        free_node(np);
        gMibError = MODULE_SYNTAX_ERROR;
        return (NULL);
    }

    np->next->parent = np->parent;
    np->parent = (char *) malloc(strlen(np->parent) + 2);
    if (np->parent == NULL) {
        free_node(np->next);
        free_node(np);
        return (NULL);
    }
    strcpy(np->parent, np->next->parent);
    strcat(np->parent, "#");
    np->next->label = strdup(np->parent);
    return np;
}

/*
 * Parses a NOTIFICATION-TYPE macro.
 * Returns 0 on error.
 */
static struct node *
parse_notificationDefinition(FILE * fp, char *name)
{
     int    type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
     struct node *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {

                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;
        case REFERENCE:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case OBJECTS:
            np->varbinds = getVarbinds(fp, &np->varbinds);
            if (!np->varbinds) {
                free_node(np);
                return NULL;
            }
            break;
        default:
            /*
             * NOTHING
             */
            break;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    return merge_parse_objectid(np, fp, name);
}

/*
 * Parses a compliance macro
 * Returns 0 on error.
 */
static int
eat_syntax(FILE * fp, char *token, int maxtoken)
{
    int             type, nexttype;
    struct node    *np = alloc_node(current_module);
    char            nexttoken[MAXTOKEN];

    if (!np)
    return 0;

    type = get_token(fp, token, maxtoken);
    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    switch (type) {
    case INTEGER:
    case INTEGER32:
    case UINTEGER32:
    case UNSIGNED32:
    case COUNTER:
    case GAUGE:
    case BITSTRING:
    case LABEL:
        if (nexttype == LEFTBRACKET) {
            /*
             * if there is an enumeration list, parse it
             */
            np->enums = parse_enumlist(fp, &np->enums);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        } else if (nexttype == LEFTPAREN) {
            /*
             * if there is a range list, parse it
             */
            np->ranges = parse_ranges(fp, &np->ranges);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        break;
    case OCTETSTR:
    case KW_OPAQUE:
        /*
         * parse any SIZE specification
         */
        if (nexttype == LEFTPAREN) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            if (nexttype == SIZE) {
                nexttype = get_token(fp, nexttoken, MAXTOKEN);
                if (nexttype == LEFTPAREN) {
                    np->ranges = parse_ranges(fp, &np->ranges);
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);      /* ) */
                    if (nexttype == RIGHTPAREN) {
                        nexttype = get_token(fp, nexttoken, MAXTOKEN);
                        break;
                    }
                }
            }

            free_node(np);
            return nexttype;
        }
        break;
    case OBJID:
    case NETADDR:
    case IPADDR:
    case TIMETICKS:
    case NUL:
    case NSAPADDRESS:
    case COUNTER64:
        break;
    default:

        free_node(np);
        return nexttype;
    }
    free_node(np);
    return nexttype;
}

static struct node *
parse_compliance(FILE * fp, char *name)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct node    *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type != STATUS) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != DEPRECATED && type != OBSOLETE) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {

        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {

        goto skip;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_SAVE_MIB_DESCRS))
        np->description = strdup(quoted_string_buffer);
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXTOKEN);
        if (type != QUOTESTRING) {

            goto skip;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != MODULE) {

        goto skip;
    }
    while (type == MODULE) {
        int             modid = -1;
        char            modname[MAXTOKEN];
        type = get_token(fp, token, MAXTOKEN);
        if (type == LABEL
            && strcmp(token, module_name(current_module, modname))) {
            modid = read_module_internal(token);
            if (modid != MODULE_LOADED_OK
                && modid != MODULE_ALREADY_LOADED) {

                goto skip;
            }
            modid = which_module(token);
            type = get_token(fp, token, MAXTOKEN);
        }
        if (type == MANDATORYGROUPS) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LEFTBRACKET) {

                goto skip;
            }
            do {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {

                    goto skip;
                }

                type = get_token(fp, token, MAXTOKEN);
            } while (type == COMMA);
            if (type != RIGHTBRACKET) {

                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
        while (type == GROUP || type == OBJECT) {
            if (type == GROUP) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {

                    goto skip;
                }

                type = get_token(fp, token, MAXTOKEN);
            } else {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {

                    goto skip;
                }

                type = get_token(fp, token, MAXTOKEN);
                if (type == SYNTAX)
                    type = eat_syntax(fp, token, MAXTOKEN);
                if (type == WRSYNTAX)
                    type = eat_syntax(fp, token, MAXTOKEN);
                if (type == MINACCESS) {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != NOACCESS && type != ACCNOTIFY
                        && type != READONLY && type != WRITEONLY
                        && type != READCREATE && type != READWRITE) {

                        goto skip;
                    }
                    type = get_token(fp, token, MAXTOKEN);
                }
            }
            if (type != DESCRIPTION) {

                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != QUOTESTRING) {

                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
    }
  skip:
    while (type != EQUALS && type != ENDOFFILE)
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);

    return merge_parse_objectid(np, fp, name);
}

/*
 * Parses a capabilities macro
 * Returns 0 on error.
 */
static struct node *
parse_capabilities(FILE * fp, char *name)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct node    *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type != PRODREL) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != QUOTESTRING) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != STATUS) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != OBSOLETE) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {

        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXTOKEN);
    if (type != QUOTESTRING) {

        goto skip;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXTOKEN);
        if (type != QUOTESTRING) {

            goto skip;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, type);
    }
    while (type == SUPPORTS) {
        int             modid;
        struct tree    *tp;

        type = get_token(fp, token, MAXTOKEN);
        if (type != LABEL) {

            goto skip;
        }
        modid = read_module_internal(token);
        if (modid != MODULE_LOADED_OK && modid != MODULE_ALREADY_LOADED) {

            goto skip;
        }
        modid = which_module(token);
        type = get_token(fp, token, MAXTOKEN);
        if (type != INCLUDES) {

            goto skip;
        }
        type = get_token(fp, token, MAXTOKEN);
        if (type != LEFTBRACKET) {

            goto skip;
        }
        do {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {

                goto skip;
            }
            tp = find_tree_node(token, modid);

            type = get_token(fp, token, MAXTOKEN);
        } while (type == COMMA);
        if (type != RIGHTBRACKET) {

            goto skip;
        }
        type = get_token(fp, token, MAXTOKEN);
        while (type == VARIATION) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {

                goto skip;
            }
            tp = find_tree_node(token, modid);

            type = get_token(fp, token, MAXTOKEN);
            if (type == SYNTAX) {
                type = eat_syntax(fp, token, MAXTOKEN);
            }
            if (type == WRSYNTAX) {
                type = eat_syntax(fp, token, MAXTOKEN);
            }
            if (type == ACCESS) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != ACCNOTIFY && type != READONLY
                    && type != READWRITE && type != READCREATE
                    && type != WRITEONLY && type != NOTIMPL) {

                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type == CREATEREQ) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LEFTBRACKET) {

                    goto skip;
                }
                do {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != LABEL) {

                        goto skip;
                    }
                    type = get_token(fp, token, MAXTOKEN);
                } while (type == COMMA);
                if (type != RIGHTBRACKET) {

                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type == DEFVAL) {
                int             level = 1;
                type = get_token(fp, token, MAXTOKEN);
                if (type != LEFTBRACKET) {

                    goto skip;
                }
                do {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type == LEFTBRACKET)
                        level++;
                    else if (type == RIGHTBRACKET)
                        level--;
                } while ((type != RIGHTBRACKET || level != 0)
                         && type != ENDOFFILE);
                if (type != RIGHTBRACKET) {

                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type != DESCRIPTION) {

                goto skip;
            }
            type = get_token(fp, quoted_string_buffer, MAXTOKEN);
            if (type != QUOTESTRING) {

                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
    }

  skip:
    while (type != EQUALS && type != ENDOFFILE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    }
    return merge_parse_objectid(np, fp, name);
}


static struct node *
parse_moduleIdentity(FILE * fp, char *name)
{
    int    type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct node *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type != LASTUPDATED) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != QUOTESTRING) {

        goto skip;
    }
    //check_utc(token);
    type = get_token(fp, token, MAXTOKEN);
    if (type != ORGANIZATION) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != QUOTESTRING) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CONTACTINFO) {

        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {

        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {

        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {

        goto skip;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    while (type == REVISION) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != QUOTESTRING) {

            goto skip;
        }
        //check_utc(token);
        type = get_token(fp, token, MAXTOKEN);
        if (type != DESCRIPTION) {

            goto skip;
        }
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {

            goto skip;
        }
        type = get_token(fp, token, MAXTOKEN);
    }

  skip:
    while (type != EQUALS && type != ENDOFFILE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    }
    return merge_parse_objectid(np, fp, name);
}

/*
 * Parses an asn type.  Structures are ignored by this parser.
 * Returns NULL on error.
 */
static struct node *
parse_asntype(FILE * fp, char *name, int *ntype, char *ntoken)
{
    int             type, i;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    char           *hint = NULL;
    char           *descr = NULL;
    struct tc      *tcp;
    int             level;

    type = get_token(fp, token, MAXTOKEN);
    if (type == SEQUENCE || type == CHOICE) {
        level = 0;
        while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE) {
            if (type == LEFTBRACKET) {
                level++;
            } else if (type == RIGHTBRACKET && --level == 0) {
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                return NULL;
            }
        }
        return NULL;
    } else if (type == LEFTBRACKET) {
        struct node    *np;
        int             ch_next = '{';
        ungetc(ch_next, fp);
        np = parse_objectid(fp, name);
        if (np != NULL) {
            *ntype = get_token(fp, ntoken, MAXTOKEN);
            return np;
        }
        return NULL;
    } else if (type == LEFTSQBRACK) {
        int             size = 0;
        do {
            type = get_token(fp, token, MAXTOKEN);
        } while (type != ENDOFFILE && type != RIGHTSQBRACK);
        if (type != RIGHTSQBRACK) {
            return NULL;
        }
        type = get_token(fp, token, MAXTOKEN);
        if (type == IMPLICIT)
            type = get_token(fp, token, MAXTOKEN);
        *ntype = get_token(fp, ntoken, MAXTOKEN);
        if (*ntype == LEFTPAREN) {
            switch (type) {
            case OCTETSTR:
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (*ntype != SIZE) {
                    return NULL;
                }
                size = 1;
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (*ntype != LEFTPAREN) {

                    return NULL;
                }
                /* FALL THROUGH */
            case INTEGER:
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                do {
                    *ntype = get_token(fp, ntoken, MAXTOKEN);
                    if (*ntype == RANGE) {
                        *ntype = get_token(fp, ntoken, MAXTOKEN);
                        *ntype = get_token(fp, ntoken, MAXTOKEN);
                    }
                } while (*ntype == BAR);
                if (*ntype != RIGHTPAREN) {

                    return NULL;
                }
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (size) {
                    if (*ntype != RIGHTPAREN) {

                        return NULL;
                    }
                    *ntype = get_token(fp, ntoken, MAXTOKEN);
                }
            }
        }
        return NULL;
    } else {
        if (type == CONVENTION) {
            while (type != SYNTAX && type != ENDOFFILE) {
                if (type == DISPLAYHINT) {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != QUOTESTRING) {

                    } else {
                        free(hint);
                        hint = strdup(token);
                    }
                } else if (type == DESCRIPTION &&
                           netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                                  NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
                    if (type != QUOTESTRING) {

                    } else {
                        free(descr);
                        descr = strdup(quoted_string_buffer);
                    }
                } else
                    type =
                        get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type == OBJECT) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != IDENTIFIER) {

                    goto err;
                }
                type = OBJID;
            }
        } else if (type == OBJECT) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != IDENTIFIER) {

                goto err;
            }
            type = OBJID;
        }

        if (type == LABEL) {
            type = get_tc(token, current_module, NULL, NULL, NULL, NULL);
        }

        /*
         * textual convention
         */
        for (i = 0; i < tc_alloc; i++) {
            if (tclist[i].type == 0)
                break;
        }

        if (i == tc_alloc) {
            tclist = (struct tc*) realloc(tclist, (tc_alloc + TC_INCR)*sizeof(struct tc));
            memset(tclist+tc_alloc, 0, TC_INCR*sizeof(struct tc));
            tc_alloc += TC_INCR;
        }
        if (!(type & SYNTAX_MASK)) {

            goto err;
        }
        tcp = &tclist[i];
        tcp->modid = current_module;
        tcp->descriptor = strdup(name);
        tcp->hint = hint;
        tcp->description = descr;
        tcp->type = type;
        *ntype = get_token(fp, ntoken, MAXTOKEN);
        if (*ntype == LEFTPAREN) {
            tcp->ranges = parse_ranges(fp, &tcp->ranges);
            *ntype = get_token(fp, ntoken, MAXTOKEN);
        } else if (*ntype == LEFTBRACKET) {
            /*
             * if there is an enumeration list, parse it
             */
            tcp->enums = parse_enumlist(fp, &tcp->enums);
            *ntype = get_token(fp, ntoken, MAXTOKEN);
        }
        return NULL;
    }

err:
    SNMP_FREE(descr);
    SNMP_FREE(hint);
    return NULL;
}

/*
 * Parses a mib file and returns a linked list of nodes found in the file.
 * Returns NULL on error.
 */
static struct node *
parse(FILE * fp, struct node *root)
{
#ifdef TEST
    extern void     xmalloc_stats(FILE *);
#endif
    char            token[MAXTOKEN];
    char            name[MAXTOKEN+1];
    int             type = LABEL;
    int             lasttype = LABEL;

#define BETWEEN_MIBS          1
#define IN_MIB                2
    int             state = BETWEEN_MIBS;
    struct node    *np, *nnp;
    struct objgroup *oldgroups = NULL, *oldobjects = NULL, *oldnotifs =
        NULL;

   // DEBUGMSGTL(("parse-file", "Parsing file:  %s...\n", File));

    if (last_err_module)
        free(last_err_module);
    last_err_module = NULL;

    np = root;
    if (np != NULL) {
        /*
         * now find end of chain
         */
        while (np->next)
            np = np->next;
    }

    while (type != ENDOFFILE) {
        if (lasttype == CONTINUE)
            lasttype = type;
        else
            type = lasttype = get_token(fp, token, MAXTOKEN);

        switch (type) {
        case END:
            if (state != IN_MIB) {
               // print_error("Error, END before start of MIB", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            } else {
                struct module  *mp;
#ifdef TEST
                printf("\nNodes for Module %s:\n", name);
                print_nodes(stdout, root);
#endif
                for (mp = module_head; mp; mp = mp->next)
                    if (mp->modid == current_module)
                        break;
                scan_objlist(root, mp, objgroups, "Undefined OBJECT-GROUP");
                scan_objlist(root, mp, objects, "Undefined OBJECT");
                scan_objlist(root, mp, notifs, "Undefined NOTIFICATION");
                objgroups = oldgroups;
                objects = oldobjects;
                notifs = oldnotifs;
                do_linkup(mp, root);
                np = root = NULL;
            }
            state = BETWEEN_MIBS;
#ifdef TEST
            if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_MIB_WARNINGS)) {
                /* xmalloc_stats(stderr); */
        }
#endif
            continue;
        case IMPORTS:
            parse_imports(fp);
            continue;
        case EXPORTS:
            while (type != SEMI && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            continue;
        case LABEL:
        case INTEGER:
        case INTEGER32:
        case UINTEGER32:
        case UNSIGNED32:
        case COUNTER:
        case COUNTER64:
        case GAUGE:
        case IPADDR:
        case NETADDR:
        case NSAPADDRESS:
        case OBJSYNTAX:
        case APPSYNTAX:
        case SIMPLESYNTAX:
        case OBJNAME:
        case NOTIFNAME:
        case KW_OPAQUE:
        case TIMETICKS:
            break;
        case ENDOFFILE:
            continue;
        default:
            strlcpy(name, token, sizeof(name));
            type = get_token(fp, token, MAXTOKEN);
            nnp = NULL;
            if (type == MACRO) {
                nnp = parse_macro(fp, name);
                if (nnp == NULL) {
                    //print_error("Bad parse of MACRO", NULL, type);
                    gMibError = MODULE_SYNTAX_ERROR;
                    /*
                     * return NULL;
                     */
                }
                free_node(nnp); /* IGNORE */
                nnp = NULL;
            }
            continue;           /* see if we can parse the rest of the file */
        }
        strlcpy(name, token, sizeof(name));
        type = get_token(fp, token, MAXTOKEN);
        nnp = NULL;

        /*
         * Handle obsolete method to assign an object identifier to a
         * module
         */
        if (lasttype == LABEL && type == LEFTBRACKET) {
            while (type != RIGHTBRACKET && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            if (type == ENDOFFILE) {
               // print_error("Expected \"}\"", token, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
        }

        switch (type) {
        case DEFINITIONS:
            if (state != BETWEEN_MIBS) {
                //print_error("Error, nested MIBS", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            state = IN_MIB;
            current_module = which_module(name);
            oldgroups = objgroups;
            objgroups = NULL;
            oldobjects = objects;
            objects = NULL;
            oldnotifs = notifs;
            notifs = NULL;
            if (current_module == -1) {
                new_module(name, File);
                current_module = which_module(name);
            }
            //DEBUGMSGTL(("parse-mibs", "Parsing MIB: %d %s\n",
                        //current_module, name));
            while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE)
                if (type == BEGIN)
                    break;
            break;
        case OBJTYPE:
            nnp = parse_objecttype(fp, name);
            if (nnp == NULL) {
                //print_error("Bad parse of OBJECT-TYPE", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJGROUP:
            nnp = parse_objectgroup(fp, name, OBJECTS, &objects);
            if (nnp == NULL) {
                //print_error("Bad parse of OBJECT-GROUP", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case NOTIFGROUP:
            nnp = parse_objectgroup(fp, name, NOTIFICATIONS, &notifs);
            if (nnp == NULL) {
                //print_error("Bad parse of NOTIFICATION-GROUP", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case TRAPTYPE:
            nnp = parse_trapDefinition(fp, name);
            if (nnp == NULL) {
                //print_error("Bad parse of TRAP-TYPE", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case NOTIFTYPE:
            nnp = parse_notificationDefinition(fp, name);
            if (nnp == NULL) {
                //print_error("Bad parse of NOTIFICATION-TYPE", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case COMPLIANCE:
            nnp = parse_compliance(fp, name);
            if (nnp == NULL) {
                //print_error("Bad parse of MODULE-COMPLIANCE", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case AGENTCAP:
            nnp = parse_capabilities(fp, name);
            if (nnp == NULL) {
               // print_error("Bad parse of AGENT-CAPABILITIES", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case MACRO:
            nnp = parse_macro(fp, name);
            if (nnp == NULL) {
                //print_error("Bad parse of MACRO", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                /*
                 * return NULL;
                 */
            }
            free_node(nnp);     /* IGNORE */
            nnp = NULL;
            break;
        case MODULEIDENTITY:
            nnp = parse_moduleIdentity(fp, name);
            if (nnp == NULL) {
                //print_error("Bad parse of MODULE-IDENTITY", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJIDENTITY:
            nnp = parse_objectgroup(fp, name, OBJECTS, &objects);
            if (nnp == NULL) {
                //print_error("Bad parse of OBJECT-IDENTITY", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJECT:
            type = get_token(fp, token, MAXTOKEN);
            if (type != IDENTIFIER) {
                //print_error("Expected IDENTIFIER", token, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != EQUALS) {
               //print_error("Expected \"::=\"", token, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            nnp = parse_objectid(fp, name);
            if (nnp == NULL) {
                //print_error("Bad parse of OBJECT IDENTIFIER", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case EQUALS:
            nnp = parse_asntype(fp, name, &type, token);
            lasttype = CONTINUE;
            break;
        case ENDOFFILE:
            break;
        default:
            //print_error("Bad operator", token, type);
            gMibError = MODULE_SYNTAX_ERROR;
            return NULL;
        }
        if (nnp) {
            if (np)
                np->next = nnp;
            else
                np = root = nnp;
            while (np->next)
                np = np->next;
            if (np->type == TYPE_OTHER)
                np->type = type;
        }
    }
    //DEBUGMSGTL(("parse-file", "End of file (%s)\n", File));
    return root;
}

/*
 * Parses a mib file and returns a linked list of nodes found in the file.
 * Returns NULL on error.
 */
/*
static struct node *
parse(FILE * fp, struct node *root)
{
    char            token[MAXTOKEN];
    char            name[MAXTOKEN+1];
    int             type = LABEL;
    int             lasttype = LABEL;

#define BETWEEN_MIBS          1
#define IN_MIB                2
    int             state = BETWEEN_MIBS;
    struct node    *np, *nnp;
    struct objgroup *oldgroups = NULL, *oldobjects = NULL, *oldnotifs =
        NULL;
    np = root;
    if (np != NULL) {
       */ /*
         * now find end of chain
         *//*
        while (np->next)
            np = np->next;
    }

    while (type != ENDOFFILE) {
        if (lasttype == CONTINUE)
            lasttype = type;
        else
            type = lasttype = get_token(fp, token, MAXTOKEN);

        switch (type) {
        case END:
            if (state != IN_MIB) {
                std::cout << "Error, END before start of MIB" << std::endl;
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            } else {
                struct module  *mp;

                for (mp = module_head; mp; mp = mp->next)
                    if (mp->modid == current_module)
                        break;
                scan_objlist(root, mp, objgroups, "Undefined OBJECT-GROUP");
                scan_objlist(root, mp, objects, "Undefined OBJECT");
                scan_objlist(root, mp, notifs, "Undefined NOTIFICATION");
                objgroups = oldgroups;
                objects = oldobjects;
                notifs = oldnotifs;
                do_linkup(mp, root);
                np = root = NULL;
            }
            state = BETWEEN_MIBS;
            continue;
        case IMPORTS:
            parse_imports(fp);
            continue;
        case EXPORTS:
            while (type != SEMI && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            continue;
        case LABEL:
        case INTEGER:
        case INTEGER32:
        case UINTEGER32:
        case UNSIGNED32:
        case COUNTER:
        case COUNTER64:
        case GAUGE:
        case IPADDR:
        case NETADDR:
        case NSAPADDRESS:
        case OBJSYNTAX:
        case APPSYNTAX:
        case SIMPLESYNTAX:
        case OBJNAME:
        case NOTIFNAME:
        case KW_OPAQUE:
        case TIMETICKS:
            break;
        case ENDOFFILE:
            continue;
        default:
            strlcpy(name, token, sizeof(name));
            type = get_token(fp, token, MAXTOKEN);
            nnp = NULL;
            if (type == MACRO) {
                nnp = parse_macro(fp, name);
                if (nnp == NULL) {
                    gMibError = MODULE_SYNTAX_ERROR;
               }
                free_node(nnp);
                nnp = NULL;
            } else
            continue;          */ /* see if we can parse the rest of the file */
     /* }
        strlcpy(name, token, sizeof(name));
        type = get_token(fp, token, MAXTOKEN);
        nnp = NULL;

       */ /*
         * Handle obsolete method to assign an object identifier to a
         * module
         */
       /* if (lasttype == LABEL && type == LEFTBRACKET) {
            while (type != RIGHTBRACKET && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            if (type == ENDOFFILE) {
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
        }

        switch (type) {
        case DEFINITIONS:
            if (state != BETWEEN_MIBS) {
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            state = IN_MIB;
            current_module = which_module(name);
            oldgroups = objgroups;
            objgroups = NULL;
            oldobjects = objects;
            objects = NULL;
            oldnotifs = notifs;
            notifs = NULL;
            if (current_module == -1) {
                new_module(name, File);
                current_module = which_module(name);
            }
            while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE)
                if (type == BEGIN)
                    break;
            break;
        case OBJTYPE:
            nnp = parse_objecttype(fp, name);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJGROUP:
            nnp = parse_objectgroup(fp, name, OBJECTS, &objects);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case NOTIFGROUP:
            nnp = parse_objectgroup(fp, name, NOTIFICATIONS, &notifs);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case TRAPTYPE:
            nnp = parse_trapDefinition(fp, name);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case NOTIFTYPE:
            nnp = parse_notificationDefinition(fp, name);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case COMPLIANCE:
            nnp = parse_compliance(fp, name);
            if (nnp == NULL) {
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case AGENTCAP:
            nnp = parse_capabilities(fp, name);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case MACRO:
            nnp = parse_macro(fp, name);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
               */ /*
                 * return NULL;
                 */
           /* }
            free_node(nnp);  */   /* IGNORE */ /*
            nnp = NULL;
            break;
        case MODULEIDENTITY:
            nnp = parse_moduleIdentity(fp, name);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJIDENTITY:
            nnp = parse_objectgroup(fp, name, OBJECTS, &objects);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJECT:
            type = get_token(fp, token, MAXTOKEN);
            if (type != IDENTIFIER) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != EQUALS) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            nnp = parse_objectid(fp, name);
            if (nnp == NULL) {

                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case EQUALS:
            nnp = parse_asntype(fp, name, &type, token);
            lasttype = CONTINUE;
            break;
        case ENDOFFILE:
            break;
        default:

            gMibError = MODULE_SYNTAX_ERROR;
            return NULL;
        }
        if (nnp) {
            if (np)
                np->next = nnp;
            else
                np = root = nnp;
            while (np->next)
                np = np->next;
            if (np->type == TYPE_OTHER)
                np->type = type;
        }
    }
    return root;
}
*/
/*
 * Returns the root of the whole tree
 *   (for backwards compatability)
 */
struct tree    *
read_mib(const char *filename)
{
    FILE           *fp;
    char            token[MAXTOKEN];

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return NULL;
    }
    mibLine = 1;
    File = filename;
    if (get_token(fp, token, MAXTOKEN) != LABEL) {
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    new_module(token, filename);
    (void) netsnmp_read_module(token);

    return tree_head;
}

void
adopt_orphans(void)
{
    struct node    *np, *onp;
    struct tree    *tp;
    int             i, adopted = 1;

    if (!orphan_nodes)
        return;
    init_node_hash(orphan_nodes);
    orphan_nodes = NULL;

    while (adopted) {
        adopted = 0;
        for (i = 0; i < NHASHSIZE; i++)
            if (nbuckets[i]) {
                for (np = nbuckets[i]; np != NULL; np = np->next) {
                    tp = find_tree_node(np->parent, -1);
            if (tp) {
            do_subtree(tp, &np);
            adopted = 1;
                        /*
                         * if do_subtree adopted the entire bucket, stop
                         */
                        if(NULL == nbuckets[i])
                            break;

                        /*
                         * do_subtree may modify nbuckets, and if np
                         * was adopted, np->next probably isn't an orphan
                         * anymore. if np is still in the bucket (do_subtree
                         * didn't adopt it) keep on plugging. otherwise
                         * start over, at the top of the bucket.
                         */
                        for(onp = nbuckets[i]; onp; onp = onp->next)
                            if(onp == np)
                                break;
                        if(NULL == onp) { /* not in the list */
                            np = nbuckets[i]; /* start over */
                        }
            }
        }
            }
    }

    /*
     * Report on outstanding orphans
     *    and link them back into the orphan list
     */
    for (i = 0; i < NHASHSIZE; i++)
        if (nbuckets[i]) {
            if (orphan_nodes)
                onp = np->next = nbuckets[i];
            else
                onp = orphan_nodes = nbuckets[i];
            nbuckets[i] = NULL;
            while (onp) {
                np = onp;
                onp = onp->next;
            }
        }
}

struct tree    *
read_all_mibs(void)
{
    struct module  *mp;
    for (mp = module_head; mp; mp = mp->next)
        if (mp->no_imports == -1)
            netsnmp_read_module(mp->name);            
    adopt_orphans();
    /* If entered the syntax error loop in "read_module()" */
    if (gLoop == 1) {
        gLoop = 0;
        free(gpMibErrorString);
        gpMibErrorString = NULL;
    }

    /* Caller's responsibility to free this memory */
    tree_head->parseErrorString = gpMibErrorString;

    return tree_head;
}

void init_mib(const char *dirname){
    netsnmp_init_mib_internals();
    add_mibdir(dirname);
    read_all_mibs();
}

int
sprint_realloc_variable(u_char ** buf, size_t * buf_len,
                        size_t * out_len, int allow_realloc,
                        const oid * objid, size_t objidlen,
                        const netsnmp_variable_list * variable)
{
    int             buf_overflow = 0;
    struct tree    *subtree = tree_head;

    subtree =
        netsnmp_sprint_realloc_objid_tree(buf, buf_len, out_len,
                                          allow_realloc, &buf_overflow,
                                          objid, objidlen);

    if (buf_overflow) {
        return 0;
    }

    if (!snmp_strcat
        (buf, buf_len, out_len, allow_realloc,
                     (const u_char *) " = ")) {
        return 0;
    }

    if (variable->type == SNMP_NOSUCHOBJECT) {
        return snmp_strcat(buf, buf_len, out_len, allow_realloc,
                           (const u_char *)
                           "No Such Object available on this agent at this OID");
    } else if (variable->type == SNMP_NOSUCHINSTANCE) {
        return snmp_strcat(buf, buf_len, out_len, allow_realloc,
                           (const u_char *)
                           "No Such Instance currently exists at this OID");
    } else if (variable->type == SNMP_ENDOFMIBVIEW) {
        return snmp_strcat(buf, buf_len, out_len, allow_realloc,
                           (const u_char *)
                           "No more variables left in this MIB View (It is past the end of the MIB tree)");
    } else if (subtree) {
        const char *units = NULL;
        const char *hint = NULL;
        if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                    NETSNMP_DS_LIB_DONT_PRINT_UNITS)) {
            units = subtree->units;
        }

        if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                    NETSNMP_DS_LIB_NO_DISPLAY_HINT)) {
            hint = subtree->hint;
        }

        if (subtree->printomat) {
            return (*subtree->printomat) (buf, buf_len, out_len,
                                          allow_realloc, variable,
                                          subtree->enums, NULL,
                                          NULL);
        } else {
            return sprint_realloc_by_type(buf, buf_len, out_len,
                                          allow_realloc, variable,
                                          subtree->enums, NULL,
                                          NULL);
        }
    } else {
        /*
         * Handle rare case where tree is empty.
         */
        return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
                                      variable, NULL, NULL, NULL);
    }
}


bool
realloc_format_plain_trap(u_char ** buf, size_t * buf_len,
                          size_t * out_len, bool allow_realloc,
                          snmp_pdu *pdu)

     /*
      * Function:
      *    Format the trap information in the default way and put the results
      * into the buffer, truncating at the buffer's length limit. This
      * routine returns 1 if the output was completed successfully or
      * 0 if it is truncated due to a memory allocation failure.
      *
      * Input Parameters:
      *    buf, buf_len, out_len, allow_realloc - standard relocatable
      *                                           buffer parameters
      *    pdu       - the pdu information
      */
{
        netsnmp_variable_list *vars;        /* variables assoc with trap */    /*
         * Output the PDU variables.
         */


        for (vars = pdu->variables; vars != NULL; vars = vars->next_variable) {
            if (!snmp_strcat
                (buf, buf_len, out_len, allow_realloc,
                 (const u_char *) "\t")) {
                return false;
            }
            if (!sprint_realloc_variable(buf, buf_len, out_len, allow_realloc,
                                         vars->name, vars->name_length,
                                         vars)) {
                return false;
            }
            if (!snmp_strcat
                    (buf, buf_len, out_len, allow_realloc, (const u_char *) "\n")) {
                    return false;
            }

             /*
             * String is already null-terminated.  That's all folks!
             */

        }
         return true;
    }
/*
 *  Trap handler for logging to a file
 */
bool print_handler(snmp_pdu *pdu)
{
    u_char         *rbuf = NULL;
    size_t          r_len = 64, o_len = 0;

    if ((rbuf = (u_char *) calloc(r_len, 1)) == NULL) {
            std::cout << "couldn't display trap -- malloc failed\n";
            return false;	/* Failed but keep going */
    }
    bool result = realloc_format_plain_trap(&rbuf, &r_len, &o_len, true,
                                                       pdu);
    for(size_t i=0;i<o_len; i++){
        std::cout << rbuf[i];
    }
    return result;
}

