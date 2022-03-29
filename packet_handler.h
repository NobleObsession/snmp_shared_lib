#ifndef SNMP_SHARED_LIB_PACKET_HANDLER_H
#define SNMP_SHARED_LIB_PACKET_HANDLER_H

#include "packet_parser.h"
#include "mib_handler.h"

std::string HandleMibPacket(u_char* received_packet, size_t packet_size, const char* mib_dir);

#endif //SNMP_SHARED_LIB_PACKET_HANDLER_H
