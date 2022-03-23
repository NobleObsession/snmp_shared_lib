#ifndef MIB_HANDLER_H
#define MIB_HANDLER_H

#include <cstdio>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <iostream>

#include "snmp_pdu.h"
#include "default_store.h"
#include "shared_constants.h"

/*
 * A linked list of nodes.
 */
struct node {
    struct node    *next;
    char           *label;  /* This node's (unique) textual name */
    u_long          subid;  /* This node's integer subidentifier */
    int             modid;  /* The module containing this node */
    char           *parent; /* The parent's textual name */
    int             tc_index; /* index into tclist (-1 if NA) */
    int             type;   /* The type of object this represents */
    int             access;
    int             status;
    struct enum_list *enums; /* (optional) list of enumerated integers */
    struct range_list *ranges;
    struct index_list *indexes;
    char           *augments;
    struct varbind_list *varbinds;
    char           *hint;
    char           *units;
    char           *description; /* description (a quoted string) */
    char           *reference; /* references (a quoted string) */
    char           *defaultValue;
    char           *filename;
    int             lineno;
};

#define HASHSIZE        32
#define NHASHSIZE    128
#define BUCKET(x)       (x & (HASHSIZE-1))
#define NBUCKET(x)   (x & (NHASHSIZE-1))
static struct tok *buckets[HASHSIZE];
static struct tree *tree_head;
static struct node *nbuckets[NHASHSIZE];
static struct tree *tbuckets[NHASHSIZE];
static struct module *module_head = NULL;
static int      translation_table[256];

static char     Standard_Prefix[] = ".1.3.6.1.2.1";

/*
 * Set default here as some uses of read_objid require valid pointer.
 */
static char    *Prefix = &Standard_Prefix[0];
typedef struct _PrefixList {
    const char     *str;
    int             len;
}              *PrefixListPtr, PrefixList;

/*
 * Here are the prefix strings.
 * Note that the first one finds the value of Prefix or Standard_Prefix.
 * Any of these MAY start with period; all will NOT end with period.
 * Period is added where needed.  See use of Prefix in this module.
 */
static PrefixList      mib_prefixes[] = {
    {&Standard_Prefix[0]},      /* placeholder for Prefix data */
    {".iso.org.dod.internet.mgmt.mib-2"},
    {".iso.org.dod.internet.experimental"},
    {".iso.org.dod.internet.private"},
    {".iso.org.dod.internet.snmpParties"},
    {".iso.org.dod.internet.snmpSecrets"},
    {NULL, 0}                   /* end of list */
};

#define TC_INCR 100
static struct tc {                     /* textual conventions */
    int             type;
    int             modid;
    char           *descriptor;
    char           *hint;
    struct enum_list *enums;
    struct range_list *ranges;
    char           *description;
} *tclist;
static int tc_alloc;


#define SYNTAX_MASK     0x80
/*
 * types of tokens
 * Tokens wiht the SYNTAX_MASK bit set are syntax tokens
 */
#define CONTINUE    -1
#define ENDOFFILE   0
#define LABEL       1
#define SUBTREE     2
#define SYNTAX      3
#define OBJID       (4 | SYNTAX_MASK)
#define OCTETSTR    (5 | SYNTAX_MASK)
#define INTEGER     (6 | SYNTAX_MASK)
#define NETADDR     (7 | SYNTAX_MASK)
#define IPADDR      (8 | SYNTAX_MASK)
#define COUNTER     (9 | SYNTAX_MASK)
#define GAUGE       (10 | SYNTAX_MASK)
#define TIMETICKS   (11 | SYNTAX_MASK)
#define KW_OPAQUE   (12 | SYNTAX_MASK)
#define NUL         (13 | SYNTAX_MASK)
#define SEQUENCE    14
#define OF          15          /* SEQUENCE OF */
#define OBJTYPE     16
#define ACCESS      17
#define READONLY    18
#define READWRITE   19
#define WRITEONLY   20
#define NOACCESS    21
#define STATUS      22
#define MANDATORY   23
#define KW_OPTIONAL    24
#define OBSOLETE    25
/*
 * #define RECOMMENDED 26
 */
#define PUNCT       27
#define EQUALS      28
#define NUMBER      29
#define LEFTBRACKET 30
#define RIGHTBRACKET 31
#define LEFTPAREN   32
#define RIGHTPAREN  33
#define COMMA       34
#define DESCRIPTION 35
#define QUOTESTRING 36
#define INDEX       37
#define DEFVAL      38
#define DEPRECATED  39
#define SIZE        40
#define BITSTRING   (41 | SYNTAX_MASK)
#define NSAPADDRESS (42 | SYNTAX_MASK)
#define COUNTER64   (43 | SYNTAX_MASK)
#define OBJGROUP    44
#define NOTIFTYPE   45
#define AUGMENTS    46
#define COMPLIANCE  47
#define READCREATE  48
#define UNITS       49
#define REFERENCE   50
#define NUM_ENTRIES 51
#define MODULEIDENTITY 52
#define LASTUPDATED 53
#define ORGANIZATION 54
#define CONTACTINFO 55
#define UINTEGER32 (56 | SYNTAX_MASK)
#define CURRENT     57
#define DEFINITIONS 58
#define END         59
#define SEMI        60
#define TRAPTYPE    61
#define ENTERPRISE  62
/*
 * #define DISPLAYSTR (63 | SYNTAX_MASK)
 */
#define BEGIN       64
#define IMPORTS     65
#define EXPORTS     66
#define ACCNOTIFY   67
#define BAR         68
#define RANGE       69
#define CONVENTION  70
#define DISPLAYHINT 71
#define FROM        72
#define AGENTCAP    73
#define MACRO       74
#define IMPLIED     75
#define SUPPORTS    76
#define INCLUDES    77
#define VARIATION   78
#define REVISION    79
#define NOTIMPL	    80
#define OBJECTS	    81
#define NOTIFICATIONS	82
#define MODULE	    83
#define MINACCESS   84
#define PRODREL	    85
#define WRSYNTAX    86
#define CREATEREQ   87
#define NOTIFGROUP  88
#define MANDATORYGROUPS	89
#define GROUP	    90
#define OBJECT	    91
#define IDENTIFIER  92
#define CHOICE	    93
#define LEFTSQBRACK	95
#define RIGHTSQBRACK	96
#define IMPLICIT    97
#define APPSYNTAX	(98 | SYNTAX_MASK)
#define OBJSYNTAX	(99 | SYNTAX_MASK)
#define SIMPLESYNTAX	(100 | SYNTAX_MASK)
#define OBJNAME		(101 | SYNTAX_MASK)
#define NOTIFNAME	(102 | SYNTAX_MASK)
#define VARIABLES	103
#define UNSIGNED32	(104 | SYNTAX_MASK)
#define INTEGER32	(105 | SYNTAX_MASK)
#define OBJIDENTITY	106
/*
 * Beware of reaching SYNTAX_MASK (0x80)
 */

struct tok {
    const char     *name;       /* token name */
    int             len;        /* length not counting nul */
    int             token;      /* value */
    int             hash;       /* hash of name */
    struct tok     *next;       /* pointer to next in hash table */
};

static struct tok tokens[] = {
    {"obsolete", sizeof("obsolete") - 1, OBSOLETE}
    ,
    {"Opaque", sizeof("Opaque") - 1, KW_OPAQUE}
    ,
    {"optional", sizeof("optional") - 1, KW_OPTIONAL}
    ,
    {"LAST-UPDATED", sizeof("LAST-UPDATED") - 1, LASTUPDATED}
    ,
    {"ORGANIZATION", sizeof("ORGANIZATION") - 1, ORGANIZATION}
    ,
    {"CONTACT-INFO", sizeof("CONTACT-INFO") - 1, CONTACTINFO}
    ,
    {"MODULE-IDENTITY", sizeof("MODULE-IDENTITY") - 1, MODULEIDENTITY}
    ,
    {"MODULE-COMPLIANCE", sizeof("MODULE-COMPLIANCE") - 1, COMPLIANCE}
    ,
    {"DEFINITIONS", sizeof("DEFINITIONS") - 1, DEFINITIONS}
    ,
    {"END", sizeof("END") - 1, END}
    ,
    {"AUGMENTS", sizeof("AUGMENTS") - 1, AUGMENTS}
    ,
    {"not-accessible", sizeof("not-accessible") - 1, NOACCESS}
    ,
    {"write-only", sizeof("write-only") - 1, WRITEONLY}
    ,
    {"NsapAddress", sizeof("NsapAddress") - 1, NSAPADDRESS}
    ,
    {"UNITS", sizeof("Units") - 1, UNITS}
    ,
    {"REFERENCE", sizeof("REFERENCE") - 1, REFERENCE}
    ,
    {"NUM-ENTRIES", sizeof("NUM-ENTRIES") - 1, NUM_ENTRIES}
    ,
    {"BITSTRING", sizeof("BITSTRING") - 1, BITSTRING}
    ,
    {"BIT", sizeof("BIT") - 1, CONTINUE}
    ,
    {"BITS", sizeof("BITS") - 1, BITSTRING}
    ,
    {"Counter64", sizeof("Counter64") - 1, COUNTER64}
    ,
    {"TimeTicks", sizeof("TimeTicks") - 1, TIMETICKS}
    ,
    {"NOTIFICATION-TYPE", sizeof("NOTIFICATION-TYPE") - 1, NOTIFTYPE}
    ,
    {"OBJECT-GROUP", sizeof("OBJECT-GROUP") - 1, OBJGROUP}
    ,
    {"OBJECT-IDENTITY", sizeof("OBJECT-IDENTITY") - 1, OBJIDENTITY}
    ,
    {"IDENTIFIER", sizeof("IDENTIFIER") - 1, IDENTIFIER}
    ,
    {"OBJECT", sizeof("OBJECT") - 1, OBJECT}
    ,
    {"NetworkAddress", sizeof("NetworkAddress") - 1, NETADDR}
    ,
    {"Gauge", sizeof("Gauge") - 1, GAUGE}
    ,
    {"Gauge32", sizeof("Gauge32") - 1, GAUGE}
    ,
    {"Unsigned32", sizeof("Unsigned32") - 1, UNSIGNED32}
    ,
    {"read-write", sizeof("read-write") - 1, READWRITE}
    ,
    {"read-create", sizeof("read-create") - 1, READCREATE}
    ,
    {"OCTETSTRING", sizeof("OCTETSTRING") - 1, OCTETSTR}
    ,
    {"OCTET", sizeof("OCTET") - 1, CONTINUE}
    ,
    {"OF", sizeof("OF") - 1, OF}
    ,
    {"SEQUENCE", sizeof("SEQUENCE") - 1, SEQUENCE}
    ,
    {"NULL", sizeof("NULL") - 1, NUL}
    ,
    {"IpAddress", sizeof("IpAddress") - 1, IPADDR}
    ,
    {"UInteger32", sizeof("UInteger32") - 1, UINTEGER32}
    ,
    {"INTEGER", sizeof("INTEGER") - 1, INTEGER}
    ,
    {"Integer32", sizeof("Integer32") - 1, INTEGER32}
    ,
    {"Counter", sizeof("Counter") - 1, COUNTER}
    ,
    {"Counter32", sizeof("Counter32") - 1, COUNTER}
    ,
    {"read-only", sizeof("read-only") - 1, READONLY}
    ,
    {"DESCRIPTION", sizeof("DESCRIPTION") - 1, DESCRIPTION}
    ,
    {"INDEX", sizeof("INDEX") - 1, INDEX}
    ,
    {"DEFVAL", sizeof("DEFVAL") - 1, DEFVAL}
    ,
    {"deprecated", sizeof("deprecated") - 1, DEPRECATED}
    ,
    {"SIZE", sizeof("SIZE") - 1, SIZE}
    ,
    {"MAX-ACCESS", sizeof("MAX-ACCESS") - 1, ACCESS}
    ,
    {"ACCESS", sizeof("ACCESS") - 1, ACCESS}
    ,
    {"mandatory", sizeof("mandatory") - 1, MANDATORY}
    ,
    {"current", sizeof("current") - 1, CURRENT}
    ,
    {"STATUS", sizeof("STATUS") - 1, STATUS}
    ,
    {"SYNTAX", sizeof("SYNTAX") - 1, SYNTAX}
    ,
    {"OBJECT-TYPE", sizeof("OBJECT-TYPE") - 1, OBJTYPE}
    ,
    {"TRAP-TYPE", sizeof("TRAP-TYPE") - 1, TRAPTYPE}
    ,
    {"ENTERPRISE", sizeof("ENTERPRISE") - 1, ENTERPRISE}
    ,
    {"BEGIN", sizeof("BEGIN") - 1, BEGIN}
    ,
    {"IMPORTS", sizeof("IMPORTS") - 1, IMPORTS}
    ,
    {"EXPORTS", sizeof("EXPORTS") - 1, EXPORTS}
    ,
    {"accessible-for-notify", sizeof("accessible-for-notify") - 1,
     ACCNOTIFY}
    ,
    {"TEXTUAL-CONVENTION", sizeof("TEXTUAL-CONVENTION") - 1, CONVENTION}
    ,
    {"NOTIFICATION-GROUP", sizeof("NOTIFICATION-GROUP") - 1, NOTIFGROUP}
    ,
    {"DISPLAY-HINT", sizeof("DISPLAY-HINT") - 1, DISPLAYHINT}
    ,
    {"FROM", sizeof("FROM") - 1, FROM}
    ,
    {"AGENT-CAPABILITIES", sizeof("AGENT-CAPABILITIES") - 1, AGENTCAP}
    ,
    {"MACRO", sizeof("MACRO") - 1, MACRO}
    ,
    {"IMPLIED", sizeof("IMPLIED") - 1, IMPLIED}
    ,
    {"SUPPORTS", sizeof("SUPPORTS") - 1, SUPPORTS}
    ,
    {"INCLUDES", sizeof("INCLUDES") - 1, INCLUDES}
    ,
    {"VARIATION", sizeof("VARIATION") - 1, VARIATION}
    ,
    {"REVISION", sizeof("REVISION") - 1, REVISION}
    ,
    {"not-implemented", sizeof("not-implemented") - 1, NOTIMPL}
    ,
    {"OBJECTS", sizeof("OBJECTS") - 1, OBJECTS}
    ,
    {"NOTIFICATIONS", sizeof("NOTIFICATIONS") - 1, NOTIFICATIONS}
    ,
    {"MODULE", sizeof("MODULE") - 1, MODULE}
    ,
    {"MIN-ACCESS", sizeof("MIN-ACCESS") - 1, MINACCESS}
    ,
    {"PRODUCT-RELEASE", sizeof("PRODUCT-RELEASE") - 1, PRODREL}
    ,
    {"WRITE-SYNTAX", sizeof("WRITE-SYNTAX") - 1, WRSYNTAX}
    ,
    {"CREATION-REQUIRES", sizeof("CREATION-REQUIRES") - 1, CREATEREQ}
    ,
    {"MANDATORY-GROUPS", sizeof("MANDATORY-GROUPS") - 1, MANDATORYGROUPS}
    ,
    {"GROUP", sizeof("GROUP") - 1, GROUP}
    ,
    {"CHOICE", sizeof("CHOICE") - 1, CHOICE}
    ,
    {"IMPLICIT", sizeof("IMPLICIT") - 1, IMPLICIT}
    ,
    {"ObjectSyntax", sizeof("ObjectSyntax") - 1, OBJSYNTAX}
    ,
    {"SimpleSyntax", sizeof("SimpleSyntax") - 1, SIMPLESYNTAX}
    ,
    {"ApplicationSyntax", sizeof("ApplicationSyntax") - 1, APPSYNTAX}
    ,
    {"ObjectName", sizeof("ObjectName") - 1, OBJNAME}
    ,
    {"NotificationName", sizeof("NotificationName") - 1, NOTIFNAME}
    ,
    {"VARIABLES", sizeof("VARIABLES") - 1, VARIABLES}
    ,
    {NULL}
};

/*
     * A linked list of tag-value pairs for enumerated integers.
     */
    struct enum_list {
        struct enum_list *next;
        int             value;
        char           *label;
    };

/*
       * A linked list of indexes
       */
      struct index_list {
         struct index_list *next;
         char           *ilabel;
         char            isimplied;
     };

/*
      * A linked list of ranges
      */
       struct range_list {
          struct range_list *next;
          int             low, high;
      };

/*
     * A tree in the format of the tree structure of the MIB.
     */
    struct tree {
        struct tree    *child_list;     /* list of children of this node */
        struct tree    *next_peer;      /* Next node in list of peers */
        struct tree    *next;   /* Next node in hashed list of names */
        struct tree    *parent;
        char           *label;  /* This node's textual name */
        u_long          subid;  /* This node's integer subidentifier */
        int             modid;  /* The module containing this node */
        int             number_modules;
        int            *module_list;    /* To handle multiple modules */
        int             tc_index;       /* index into tclist (-1 if NA) */
        int             type;   /* This node's object type */
        int             access; /* This nodes access */
        int             status; /* This nodes status */
        struct enum_list *enums;        /* (optional) list of enumerated integers */
        struct range_list *ranges;
        struct index_list *indexes;
        char           *augments;
        struct varbind_list *varbinds;
        char           *hint;
        char           *units;
        int             (*printomat) (u_char **, size_t *, size_t *, int,
                                      const netsnmp_variable_list *,
                                      const struct enum_list *, const char *,
                                      const char *);
        void            (*printer) (char *, const netsnmp_variable_list *, const struct enum_list *, const char *, const char *);   /* Value printing function */
        char           *description;    /* description (a quoted string) */
        char           *reference;    /* references (a quoted string) */
        int             reported;       /* 1=report started in print_subtree... */
        char           *defaultValue;
       char	       *parseErrorString; /* Contains the error string if there are errors in parsing MIBs */
    };

/*
 * Information held about each MIB module
 */
struct module_import {
    char           *label;  /* The descriptor being imported */
    int             modid;  /* The module imported from */
};


struct module {
        char           *name;   /* This module's name */
        char           *file;   /* The file containing the module */
        struct module_import *imports;  /* List of descriptors being imported */
        int             no_imports;     /* The number of such import descriptors */
        /*
         * -1 implies the module hasn't been read in yet
         */
        int             modid;  /* The index number of this module */
        struct module  *next;   /* Linked list pointer */
    };


struct module_compatability {
        const char     *old_module;
        const char     *new_module;
        const char     *tag;    /* NULL implies unconditional replacement,
                                 * otherwise node identifier or prefix */
        size_t          tag_len;        /* 0 implies exact match (or unconditional) */
        struct module_compatability *next;      /* linked list */
    };

#define	NUMBER_OF_ROOT_NODES	3
static struct module_import root_imports[NUMBER_OF_ROOT_NODES];

static struct module_compatability *module_map_head;
static struct module_compatability module_map[] = {
    {"RFC1065-SMI", "RFC1155-SMI", NULL, 0},
    {"RFC1066-MIB", "RFC1156-MIB", NULL, 0},
    /*
     * 'mib' -> 'mib-2'
     */
    {"RFC1156-MIB", "RFC1158-MIB", NULL, 0},
    /*
     * 'snmpEnableAuthTraps' -> 'snmpEnableAuthenTraps'
     */
    {"RFC1158-MIB", "RFC1213-MIB", NULL, 0},
    /*
     * 'nullOID' -> 'zeroDotZero'
     */
    {"RFC1155-SMI", "SNMPv2-SMI", NULL, 0},
    {"RFC1213-MIB", "SNMPv2-SMI", "mib-2", 0},
    {"RFC1213-MIB", "SNMPv2-MIB", "sys", 3},
    {"RFC1213-MIB", "IF-MIB", "if", 2},
    {"RFC1213-MIB", "IP-MIB", "ip", 2},
    {"RFC1213-MIB", "IP-MIB", "icmp", 4},
    {"RFC1213-MIB", "TCP-MIB", "tcp", 3},
    {"RFC1213-MIB", "UDP-MIB", "udp", 3},
    {"RFC1213-MIB", "SNMPv2-SMI", "transmission", 0},
    {"RFC1213-MIB", "SNMPv2-MIB", "snmp", 4},
    {"RFC1231-MIB", "TOKENRING-MIB", NULL, 0},
    {"RFC1271-MIB", "RMON-MIB", NULL, 0},
    {"RFC1286-MIB", "SOURCE-ROUTING-MIB", "dot1dSr", 7},
    {"RFC1286-MIB", "BRIDGE-MIB", NULL, 0},
    {"RFC1315-MIB", "FRAME-RELAY-DTE-MIB", NULL, 0},
    {"RFC1316-MIB", "CHARACTER-MIB", NULL, 0},
    {"RFC1406-MIB", "DS1-MIB", NULL, 0},
    {"RFC-1213", "RFC1213-MIB", NULL, 0},
};


/*
     * non-aggregate types for tree end nodes
     */
#define TYPE_OTHER          0
#define TYPE_OBJID          1
#define TYPE_OCTETSTR       2
#define TYPE_INTEGER        3
#define TYPE_NETADDR        4
#define TYPE_IPADDR         5
#define TYPE_COUNTER        6
#define TYPE_GAUGE          7
#define TYPE_TIMETICKS      8
#define TYPE_OPAQUE         9
#define TYPE_NULL           10
#define TYPE_COUNTER64      11
#define TYPE_BITSTRING      12
#define TYPE_NSAPADDRESS    13
#define TYPE_UINTEGER       14
#define TYPE_UNSIGNED32     15
#define TYPE_INTEGER32      16

#define TYPE_SIMPLE_LAST    16

#define TYPE_TRAPTYPE	    20
#define TYPE_NOTIFTYPE      21
#define TYPE_OBJGROUP	    22
#define TYPE_NOTIFGROUP	    23
#define TYPE_MODID	    24
#define TYPE_AGENTCAP       25
#define TYPE_MODCOMP        26
#define TYPE_OBJIDENTITY    27

#define MIB_ACCESS_READONLY    18
#define MIB_ACCESS_READWRITE   19
#define	MIB_ACCESS_WRITEONLY   20
#define MIB_ACCESS_NOACCESS    21
#define MIB_ACCESS_NOTIFY      67
#define MIB_ACCESS_CREATE      48

#define MIB_STATUS_MANDATORY   23
#define MIB_STATUS_OPTIONAL    24
#define MIB_STATUS_OBSOLETE    25
#define MIB_STATUS_DEPRECATED  39
#define MIB_STATUS_CURRENT     57

#define NETSNMP_STRING_OUTPUT_GUESS  1
#define NETSNMP_STRING_OUTPUT_ASCII  2
#define NETSNMP_STRING_OUTPUT_HEX    3

#define NETSNMP_OID_OUTPUT_SUFFIX  1
#define NETSNMP_OID_OUTPUT_MODULE  2
#define NETSNMP_OID_OUTPUT_FULL    3
#define NETSNMP_OID_OUTPUT_NUMERIC 4
#define NETSNMP_OID_OUTPUT_UCD     5
#define NETSNMP_OID_OUTPUT_NONE    6

#define	ANON	"anonymous#"
#define	ANON_LEN  strlen(ANON)

enum inet_address_type {
    IPV4 = 1,
    IPV6 = 2,
    IPV4Z = 3,
    IPV6Z = 4,
    DNS = 16
};

/*
 * This is one element of an object identifier with either an integer
 * subidentifier, or a textual string label, or both.
 * The subid is -1 if not present, and label is NULL if not present.
 */
struct subid_s {
    int             subid;
    int             modid;
    char           *label;
};



const static char     *File = "(none)";
static int             mibLine = 0;
static int      anonymous = 0;

#define MAXTOKEN        128     /* maximum characters in a token */
#define MAXQUOTESTR     4096    /* maximum characters in a quoted string */
#define ENDOFFILE   0
static int      max_module = 0;
static int      current_module = 0;

#define MODULE_NOT_FOUND	0
#define MODULE_LOADED_OK	1
#define MODULE_ALREADY_LOADED	2
/*
 * #define MODULE_LOAD_FAILED   3
 */
#define MODULE_LOAD_FAILED	MODULE_NOT_FOUND
#define MODULE_SYNTAX_ERROR     4

static char    *last_err_module = NULL; /* no repeats on "Cannot find module..." */
static int gMibError = 0;
static struct node *orphan_nodes = NULL;

struct objgroup {
       char           *name;
       int             line;
       struct objgroup *next;
};

static objgroup* objgroups = NULL, *objects = NULL, *notifs = NULL;


/*
     * A linked list of varbinds
     */
struct varbind_list {
      struct varbind_list *next;
      char           *vblabel;
};


static int gLoop = 0;
static char *gpMibErrorString;
#define STRINGMAX 1024
static char gMibNames[STRINGMAX];

int
add_mibdir(const char *dirname);
int
add_mibfile(const char* tmpstr, const char* d_name);

static int
name_hash(const char *name);

int
sprint_realloc_by_type(u_char ** buf, size_t * buf_len, size_t * out_len,
                       int allow_realloc,
                       const netsnmp_variable_list * var,
                       const struct enum_list *enums,
                       const char *hint, const char *units);
int
sprint_realloc_object_identifier(u_char ** buf, size_t * buf_len,
                                 size_t * out_len, int allow_realloc,
                                 const netsnmp_variable_list * var,
                                 const struct enum_list *enums,
                                 const char *hint, const char *units);

struct tree    *
netsnmp_sprint_realloc_objid_tree(u_char ** buf, size_t * buf_len,
                                  size_t * out_len, int allow_realloc,
                                  int *buf_overflow,
                                  const oid * objid, size_t objidlen);

void init_mib(const char *dirname);
void
print_subtree(FILE * f, struct tree *tree, int count);
void
netsnmp_init_mib_internals(void);
static struct node *
parse(FILE * fp, struct node *root);
static int
read_module_replacements(const char *name);
int
snmp_strcat(u_char ** buf, size_t * buf_len, size_t * out_len,
            int allow_realloc, const u_char * s);
bool print_handler(snmp_pdu* pdu);
int
sprint_realloc_timeticks(u_char ** buf, size_t * buf_len, size_t * out_len,
                         int allow_realloc,
                         const netsnmp_variable_list * var,
                         const struct enum_list *enums,
                         const char *hint, const char *units);
#endif // MIB_HANDLER_H
