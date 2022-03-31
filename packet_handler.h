#ifndef SNMP_SHARED_LIB_PACKET_HANDLER_H
#define SNMP_SHARED_LIB_PACKET_HANDLER_H

#include "packet_parser.h"
#include "mib_handler.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string>

std::string HandleMibPacket(u_char* received_packet, size_t packet_size, const char* mib_dir);

std::string AddTimestamp();

std::string AddTransportInfo(std::string& client_ip, unsigned short client_port, int host_port);

#endif //SNMP_SHARED_LIB_PACKET_HANDLER_H
