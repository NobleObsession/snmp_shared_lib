#include "packet_handler.h"
#include "memory"

std::string HandleMibPacket(u_char* data, size_t packet_size, const char* mib_dir) {

    auto pdu = std::make_shared<snmp_pdu>();
    if(!parse_pdu(data, &packet_size, pdu.get())){
        return std::string();
    }

    init_mib(mib_dir);

    size_t          r_len = 64, o_len = 0;
    u_char* parsed_trap = new u_char[r_len];
    realloc_format_plain_trap(&parsed_trap, &r_len, &o_len, true, pdu.get());

    if(!parsed_trap){
        return std::string();
    }
    return std::string(reinterpret_cast<const char*>(parsed_trap), o_len);

}

std::string AddTimestamp(){
    time_t          now;        /* the current time */
    struct tm      *now_parsed; /* time in struct format */
    time(&now);
    now_parsed = localtime(&now);
    char            safe_bfr[200];     /* holds other strings */
    sprintf(safe_bfr, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d ",
            now_parsed->tm_year + 1900, now_parsed->tm_mon + 1,
            now_parsed->tm_mday, now_parsed->tm_hour,
            now_parsed->tm_min, now_parsed->tm_sec);
    return std::string(safe_bfr);
}

/*
 * XXX  What if we have multiple addresses?  Or no addresses for that matter?
 * XXX  Could it be computed once then cached?  Probably not worth it (not
 *                                                           used very often).
 */
in_addr_t
get_myaddr(void)
{
    int             sd, i, lastlen = 0;
    struct ifconf   ifc;
    struct ifreq   *ifrp = NULL;
    in_addr_t       addr;
    char           *buf = NULL;

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return 0;
    }

    /*
     * Cope with lots of interfaces and brokenness of ioctl SIOCGIFCONF on
     * some platforms; see W. R. Stevens, ``Unix Network Programming Volume
     * I'', p.435.
     */

    for (i = 8;; i += 8) {
        buf = (char *) calloc(i, sizeof(struct ifreq));
        if (buf == NULL) {
            close(sd);
            return 0;
        }
        ifc.ifc_len = i * sizeof(struct ifreq);
        ifc.ifc_buf = (caddr_t) buf;

        if (ioctl(sd, SIOCGIFCONF, (char *) &ifc) < 0) {
            if (errno != EINVAL || lastlen != 0) {
                /*
                 * Something has gone genuinely wrong.
                 */
                free(buf);
                close(sd);
                return 0;
            }
            /*
             * Otherwise, it could just be that the buffer is too small.
             */
        } else {
            if (ifc.ifc_len == lastlen) {
                /*
                 * The length is the same as the last time; we're done.
                 */
                break;
            }
            lastlen = ifc.ifc_len;
        }
        free(buf);
    }

    for (ifrp = ifc.ifc_req;
         (char *)ifrp < (char *)ifc.ifc_req + ifc.ifc_len;
         ifrp++
            ) {
        if (ifrp->ifr_addr.sa_family != AF_INET) {
            continue;
        }
        addr = ((struct sockaddr_in *) &(ifrp->ifr_addr))->sin_addr.s_addr;

        if (ioctl(sd, SIOCGIFFLAGS, (char *) ifrp) < 0) {
            continue;
        }
        if ((ifrp->ifr_flags & IFF_UP)
            #ifdef IFF_RUNNING
            && (ifrp->ifr_flags & IFF_RUNNING)
            #endif                          /* IFF_RUNNING */
            && !(ifrp->ifr_flags & IFF_LOOPBACK)
            && addr != INADDR_LOOPBACK) {

            free(buf);
            close(sd);
            return addr;
        }
    }
    free(buf);
    close(sd);
    return 0;
}

std::string AddTransportInfo(std::string& client_ip, unsigned short client_port, int host_port){
    std::string transport_info("UDP: ");
    transport_info = transport_info + "[" + client_ip + "]";

    transport_info = transport_info + ":" + std::to_string(client_port) + "->";

    in_addr_t hostAddress = get_myaddr();
    char hostAddressStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &hostAddress, hostAddressStr, sizeof(hostAddressStr));
    transport_info =  transport_info + "[" + std::string(hostAddressStr) + "]:" + std::to_string(host_port);
    return transport_info;
}
