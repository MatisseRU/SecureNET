// PROGRAMMING, REMOVED WHEN PUSHING
#define PLATEFORM_LINUX 1
// PROGRAMMING, REMOVED WHEN PUSHING


#ifdef PLATEFORM_LINUX
    #undef PLATEFORM_WINDOWS
    #include "../platforms/linux/linux.c"
#elif PLATEFORM_WINDOWS
    #undef PLATEFORM_LINUX
    #include "../plateforms/windows/windows.c"
#endif

/* PACKETS ARE OF FIXED SIZE: */

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


int main(int argc, char **argv)
{

    return 0;
}