#include <gtest/gtest.h>

#include "packet_parser.h"

TEST(ParsePacket, ParseCommunityAndVersion_v2) {
    const char *example_packet ="30819102"
            "010104067075626c6963a78183020469"
            "1421910201000201003075301006082b"
            "0601020101030043040219a7fd301606"
            "0a2b06010603010104010006082b0601"
            "02010f0702301606102b060102010f03"
            "010e8140812803814a04020000301506"
            "102b060102010f030102814081280381"
            "4a020101301a060a2b06010603010104"
            "0300060c2b06010401944c010101020e";

    size_t packet_len = 148;
    u_char converted_packet[packet_len];
    u_char *begin = converted_packet;
    u_char *end = converted_packet + sizeof(converted_packet);
    unsigned int u;

    while (begin < end && sscanf(example_packet, "%2x", &u) == 1){
        *begin++ = u;
        example_packet += 2;
    }

    snmp_pdu pdu;
    u_char *data = converted_packet;

    u_char community[COMMUNITY_MAX_LEN];
    size_t community_length = COMMUNITY_MAX_LEN;
    data = snmp_comstr_parse(data, &packet_len,
                                         community, &community_length,
                                         &pdu.version);
    EXPECT_EQ(SNMP_VERSION_2c, pdu.version);

    const char* expected_community = "public";
    const char* parsed_community = reinterpret_cast<const char*>(community);
    EXPECT_EQ(0, strcmp(expected_community, parsed_community));
}

TEST(ParsePacket, CheckMsgType_Trap2) {
    const char *example_packet ="30819102"
            "010104067075626c6963a78183020469"
            "1421910201000201003075301006082b"
            "0601020101030043040219a7fd301606"
            "0a2b06010603010104010006082b0601"
            "02010f0702301606102b060102010f03"
            "010e8140812803814a04020000301506"
            "102b060102010f030102814081280381"
            "4a020101301a060a2b06010603010104"
            "0300060c2b06010401944c010101020e";

    size_t example_packet_size = 148;
    u_char converted_packet[example_packet_size];
    u_char *begin = converted_packet;
    u_char *end = converted_packet + sizeof(converted_packet);
    unsigned int u;

    while (begin < end && sscanf(example_packet, "%2x", &u) == 1){
        *begin++ = u;
        example_packet += 2;
    }
    snmp_pdu pdu;
    u_char *data = converted_packet;

    u_char community[COMMUNITY_MAX_LEN];
    size_t community_length = COMMUNITY_MAX_LEN;
    data = snmp_comstr_parse(data, &example_packet_size,
                                         community, &community_length,
                                         &pdu.version);
    u_char          msg_type;
    data = asn_parse_header(data, &example_packet_size, &msg_type);
    EXPECT_EQ(SNMP_MSG_TRAP2, msg_type);
}

TEST(ParsePacket, GetAndCheckOIDsFromPacket) {
    const char *example_packet ="30819102"
            "010104067075626c6963a78183020469"
            "1421910201000201003075301006082b"
            "0601020101030043040219a7fd301606"
            "0a2b06010603010104010006082b0601"
            "02010f0702301606102b060102010f03"
            "010e8140812803814a04020000301506"
            "102b060102010f030102814081280381"
            "4a020101301a060a2b06010603010104"
            "0300060c2b06010401944c010101020e";

    size_t example_packet_size = 148;
    u_char converted_packet[example_packet_size];
    u_char *begin = converted_packet;
    u_char *end = converted_packet + sizeof(converted_packet);
    unsigned int u;

    while (begin < end && sscanf(example_packet, "%2x", &u) == 1){
        *begin++ = u;
        example_packet += 2;
    }
    snmp_pdu pdu;
    u_char *data = converted_packet;

    u_char community[COMMUNITY_MAX_LEN];
    size_t community_length = COMMUNITY_MAX_LEN;
    data = snmp_comstr_parse(data, &example_packet_size,
                                         community, &community_length,
                                         &pdu.version);
    u_char          msg_type;
    u_char          type;
    data = asn_parse_header(data, &example_packet_size, &msg_type);
    data = get_preceding_fields(data, &example_packet_size, &type, &pdu);
    data = asn_parse_sequence(data, &example_packet_size, &type,
                                  (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                  "varbinds");

    get_var_bind_sequences(data, &example_packet_size, &pdu);
    EXPECT_TRUE(CheckTrapOid(&pdu));
}

