#include "default_store.h"

#define SNMPERR_GENERR			(-1)

int
netsnmp_ds_get_boolean(int storeid, int which)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
        which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return SNMPERR_GENERR;
    }

    return (netsnmp_ds_booleans[storeid][which/8] & (1 << (which % 8))) ? 1:0;
}

int
netsnmp_ds_get_int(int storeid, int which)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
        which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return SNMPERR_GENERR;
    }

    return netsnmp_ds_integers[storeid][which];
}

int
netsnmp_ds_set_int(int storeid, int which, int value)
{
    if (storeid < 0 || storeid >= NETSNMP_DS_MAX_IDS ||
    which   < 0 || which   >= NETSNMP_DS_MAX_SUBIDS) {
        return SNMPERR_GENERR;
    }


    netsnmp_ds_integers[storeid][which] = value;
    return 0;
}
