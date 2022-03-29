#include "packet_handler.h"
#include "memory"

std::string HandleMibPacket(u_char* data, size_t packet_size, const char* mib_dir) {

    auto pdu = std::make_shared<snmp_pdu>();
    get_pdu(data, &packet_size, pdu.get());

    init_mib(mib_dir);

    size_t          r_len = 64, o_len = 0;
    u_char* parsed_trap = new u_char[r_len];
    realloc_format_plain_trap(&parsed_trap, &r_len, &o_len, true, pdu.get());

    if(!parsed_trap){
        return std::string();
    }
    return std::string(reinterpret_cast<const char*>(parsed_trap), o_len);

}


