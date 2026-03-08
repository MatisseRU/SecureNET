#ifndef SNET_PROTOCOL_H
#define SNET_PROTOCOL_H

#include <stdint.h>

#define SNET_PROTOCOL_MAGIC 0x53
#define SNET_PROTOCOL_VERSION 0x01
#define SNET_PACKET_HEADER_SIZE 5

/*
 * Packet v1 header layout (5 bytes):
 *   byte 0: magic
 *   byte 1: version
 *   byte 2: opcode
 *   byte 3-4: payload length (uint16, network byte order)
 */
typedef struct SNET_packet_header_v1
{
    uint8_t magic;
    uint8_t version;
    uint8_t opcode;
    uint16_t payload_len_be;
} SNET_packet_header_v1;

/* Protocol opcodes */
#define SNET_router_unreachable 0xE0
#define SNET_connection_drop 0xE1
#define SNET_no_service 0xE2
#define SNET_protocol_error 0xE3
#define SNET_connection_refused 0xE4

#define SNET_ask_if_need_send_propagate 0xFD
#define SNET_broadcasting_do_not_propagate 0xFE
#define SNET_broadcasting_propagate 0xFF

#define SNET_ask_connection 0x10
#define SNET_ask_probation 0x11
#define SNET_vote_no 0x12
#define SNET_vote_yes 0x13
#define SNET_connection_accepted 0x14

#define SNET_new_service 0x20
#define SNET_push_to_blockchain_do_not_propagate 0x21
#define SNET_push_to_blockchain_propagate 0x22
#define SNET_ask_block 0x23
#define SNET_ask_blockchain 0x24

#define SNET_get_service 0x30
#define SNET_reply_service 0x31

#define SNET_are_you_alive 0x40
#define SNET_new_client 0x41

#define SNET_KILLSWITCH 0xF0

/* Unified I/O error codes (negative values) */
#define SNET_IO_ERR_INVALID_ARG -1
#define SNET_IO_ERR_RECV -2
#define SNET_IO_ERR_BAD_HEADER -3
#define SNET_IO_ERR_BAD_OPCODE -4
#define SNET_IO_ERR_LENGTH_OVERFLOW -5
#define SNET_IO_ERR_SEND -6
#define SNET_IO_ERR_NOT_SUPPORTED -100

#endif
