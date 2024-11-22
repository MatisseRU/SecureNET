import socket
from random import randint
import rsa

# structure of a packet
"""
    Protocol Header
    Reply Header
    Encrypted Data
"""
# protocol headers
"""
    op-code
    routing related data
"""
# every protocol headers
"""
    Op-codes:

        // pseudo TCP (over UDP and over TCP too)
        syn: 0x01
        syn_ack: 0x02
        ack: 0x03
        end_connection: 0x04

        // error handling
        router_unreachable: 0xE0
        connection_drop/cancel: 0xE1
        no_service: 0xE2
        protocol_error: 0xE3
        connection_refused: 0xE4

        ask_if_need_send_propagate: 0xFD // in case the router already received it, especially useful for only broadcasting mode (when network discovery is off)
        broadcasting_do_not_propagate: 0xFE
        broadcasting_propagate: 0xFF

        // this is used when a client tries to connect to the Secure Network
        ask_connection: 0x10
        ask_probation: 0x11 -> voting sequence
        vote_no: 0x12
        vote_yes: 0x13
        connection_accepted: 0x14



        // stored broadcast informations related.
        new_service: 0x20
        push_to_blockchain_do_not_propagate: 0x21
        push_to_blockchain_propagate: 0x22 // useful when using only broadcasting (security oriented mode) and using blockchain system
        ask_block: 0x23
        ask_blockchain: 0x24 (ask hashes, not the whole blockchain...)

        // when accessing a service
        get_service: 0x30
        reply_service: 0x31



        // mapping protocol
        are_you_alive?: 0x40
        new_client: 0x41 -> when a new router is accepted

        Recreating_Blockchain: 0xF5 -> used to "drop" the current blockchain and create/use a new one.
        KILL SWITCH: 0xF0

        Packet Segmentation:
            Not segmented:
                -> 0x...
            Segmented:
                -> part 1:
                    1x...
                -> part 2:
                    2x...
                -> part N:
                    Nx...


    Protocol Header lenghts:
        opcode + replyheader + data = 1024
 
    """
MAX_PACKET_SIZE = 2048
DEBUG = 0






#  ->>  packet generators  <<-  #


def SecureNET_SYN(pubkey:rsa.PublicKey) -> bytes:
    return rsa.encrypt(("0x01").encode(), pubkey)
def SecureNET_SYN_ACK(pubkey:rsa.PublicKey) -> bytes:
    return rsa.encrypt(("0x02").encode(), pubkey)
def SecureNET_ACK(pubkey:rsa.PublicKey) -> bytes:
    return rsa.encrypt(("0x03").encode(), pubkey)
def SecureNET_End_Connection(pubkey:rsa.PublicKey) -> bytes:
    return rsa.encrypt(("0x04").encode(), pubkey)

def SecureNET_ERR_router_unreachable() -> bytes:
    return "0xE0".encode()
def SecureNET_ERR_connection_drop_cancel() -> bytes:
    return "0xE1".encode()
def SecureNET_ERR_no_service() -> bytes:
    return "0xE2".encode()
def SecureNET_ERR_protocol_error() -> bytes:
    return "0xE3".encode()
def SecureNET_ERR_connection_refused() -> bytes:
    return "0xE4".encode()


# request
def SecureNET_ask_if_need_send_propagate(hash:str) -> bytes:
    """
    0xFD|HASH
    """
    return ("0xFD|" + hash).encode()
# request - one way
def SecureNET_broadcasting_do_not_propagate(data:str) -> bytes:
    """
    0xFE|data
    """
    return ("0xFE|" + data).encode()
# request - one way
def SecureNET_brodactasting_propagate(data:str) -> bytes:
    """
    0xFF|data
    """
    return ("0xFF|" + data).encode()

# request
def SecureNET_Ask_Connection(public_key:str, pubkey:rsa.PublicKey) -> bytes:
    """
    0x10|public_key
    """
    return rsa.encrypt(("0x10|" + public_key).encode(), pubkey)
# request
def SecureNET_Ask_Probation(cli_IP:str, cli_PubKey:str, prob_HASH:str, pubkey:rsa.PublicKey) -> bytes:
    """
    0x11|clientIP|clientPubKey|ProbationHash
    """
    return rsa.encrypt(("0x11|" + cli_IP + "|" + cli_PubKey + "|" + prob_HASH).encode(), pubkey)
# response - one way
def SecureNET_vote_no(prob_HASH:str, pubkey:rsa.PublicKey) -> bytes:
    """
    0x12|probationHash
    """
    return rsa.encrypt(("0x12|" + prob_HASH).encode(), pubkey)
# response - one way
def SecureNET_vote_yes(prob_HASH:str, pubkey:rsa.PublicKey) -> bytes:
    """
    0x13|probationHash
    """
    return rsa.encrypt(("0x13|" + prob_HASH).encode(), pubkey)
# response - one way
def SecureNET_Connection_Accepted(prob_HASH:str, pubkey:rsa.PublicKey) -> bytes:
    """
    0x14|probationHash
    """
    return rsa.encrypt(("0x14|" + prob_HASH).encode(), pubkey)

# request
def SecureNET_Are_You_Alive(pubkey:rsa.PublicKey) -> bytes:
    """
    0x40
    """
    return rsa.encrypt(("0x40").encode(), pubkey)
# request - one way
def SecureNET_New_Client(cli_IP:str, cli_port:int, cli_PubKey:str, pubkey:rsa.PublicKey) -> bytes:
    """
    0x41|clientIP|clientPORT|clientPubKey
    """
    return rsa.encrypt(("0x41|" + cli_IP + "|" + str(cli_port) + "|" + cli_PubKey).encode(), pubkey)
# request - one way
def SecureNET_KILL_SWITCH(reason:str, masterPassword:str, pubkey:rsa.PublicKey) -> bytes:
    """
    0xF0|reason|masterPassword
    """
    return rsa.encrypt(("0xF0|" + reason + "|" + masterPassword).encode(), pubkey)

# request
def SecureNET_Get_Service(service_descriptor_HASH:str, protoPort:str, repHeader:str, data:str, endPubKey:str, pubkey:rsa.PublicKey) -> bytes:
    """
    Each service has its own service descriptor and public/private key pair,
    so that the hosting router do not reveal its identity.
    
    Same for the client's side, the client generates a key pair for the entire connection.

    0x30@serviceDescriptorHash@protoPort@endPubKey|replyHeader|data
    """
    return rsa.encrypt(("0x30@" + service_descriptor_HASH + "@" + protoPort + "@" + endPubKey + "|" + repHeader + "|" + data).encode(), pubkey)
# response - one way
def SecureNET_Reply_Service(serviceDescriptorHash:str, protoPort:str, repHeader:str, data:str, pubkey:rsa.PublicKey) -> bytes:
    """
    0x31@serviceDescriptorHash@ProtoPort|RepHeader|data
    """
    return rsa.encrypt(("0x31@" + serviceDescriptorHash + "@" + protoPort + "|" + repHeader + "|" + data).encode(), pubkey)



# blockchain manipulation

def SecureNET_BC_New_Service(ServiceHash:str, dateExpiry:str, meetingAddresses:list, distPort:str, acceptedProto:str, servicePubkey:str, pubkey:rsa.PublicKey) -> bytes:
    """
    if dateExpiry < 0 (I.E. = -1), the link never expires.
    meetingAdresses is a list of SparkCrypt addresses that the service provider responds to.
    distPort is the port on which the service provider runs on its computer at the localhost address.
    acceptedProto is basically the server running behind the distPort.
    """
    return rsa.encrypt(("0x20@" + ServiceHash+"@" + dateExpiry+"@" + meetingAddresses+"@" + distPort+"@" + acceptedProto+"@" + servicePubkey).encode())
def SecureNET_BC_push_to_blockchain_do_not_propagate(data:str, pubkey:rsa.PublicKey) -> bytes:
    return rsa.encrypt(("0x21|" + data).encode(), pubkey)
def SecureNET_BC_push_to_blockchain_propagate(data:str, pubkey:rsa.PublicKey) -> bytes:
    return rsa.encrypt(("0x22|" + data).encode(), pubkey)
def SecureNET_BC_ask_block(blockHash:str, pubkey:rsa.PublicKey) -> bytes:
    return rsa.encrypt(("0x23|" + blockHash).encode(), pubkey)
def SecureNET_BC_ask_blockchain(pubkey:rsa.PublicKey) -> bytes:
    return rsa.encrypt("0x24".encode(), pubkey)



# packet manipulation
def SecureNET_do_Segment_Data(data:bytes, packetNbr:int, dataSegSize:int) -> list:
    data_list = []
    while(packetNbr != 0):
        data_list.append(data[:dataSegSize])
        data = data[dataSegSize:]
        packetNbr -= 1
    return data_list
def SecureNET_do_Fetch(header_list, data_list) -> list:
    """
    fetch the data section to the right header in order to get the desired fragmented packets
    returns a list: if the list contains ["LENGHT MISSMATCH"] it means that a either a data segment or a header
    segment is missing.
    """
    fetched_packet = []
    if(len(header_list) != len(data_list)):
        return ["LENGHT MISSMATCH"]
    for i in range(len(header_list)):
        fetched_packet.append(header_list[i] + data_list[i])
    return fetched_packet
def SecureNET_do_Add_Padding(data:bytes, nbrOfBytes:int) -> bytes:
    """
    add padding (or garbage), nbrOfBytes times, in a data or header segment.\n
    """
    random_garbage = [chr(randint(1, 254)) for i in range(nbrOfBytes)]
    garbage = ""
    for i in range(len(random_garbage)):
        garbage += random_garbage[i]

    new_segment = data[:]
    new_segment += garbage.encode()
    return new_segment

def SecureNET_do_Calculate_Nbr_of_Digits_in_maxPacketSize() -> int:
    """
    used to determine how many bytes the packet containing the size and segmentation contains.
    """
    i = float(MAX_PACKET_SIZE)
    nbr_of_digits = 0
    while(i > 0):
        i //= 10
        nbr_of_digits += 1
    return nbr_of_digits
def SecureNET_do_Send_Packet_Size_and_Segmentation(s:socket.socket, packetSize:int, packetNbrOfSegs:int, pubkey:rsa.PublicKey) -> int:
    """
    Send the size and segmentation rule of the next packet containing the actual data.\n
    Let's assume that the maxDataFieldSize is equal to 2048.\n
    We have a packetSize of 187 and it is not fragmented:\n
    the router will receive:\n
        0187|1
    """
    
    if(packetNbrOfSegs > 9):
        print("You can only fragment packets up to 9 parts ! \n")
        return -1
    data_out = str(packetSize)

    # padding
    while(SecureNET_do_Calculate_Nbr_of_Digits_in_maxPacketSize() > len(data_out)):
        data_out = "0" + data_out

    data_out = data_out + "|" + str(packetNbrOfSegs)
    if( DEBUG == 1 ):
        print(f"#DEBUG The segmentation is: {data_out} #DEBUG")
    
    s.send( rsa.encrypt(data_out.encode(), pubkey) )
    
    if( DEBUG == 1):
        print(f"#DEBUG Sent packet size and frag #DEBUG")


    return 0
def SecureNET_do_Recv_Packet_Size_and_Segmentation(s:socket.socket, privkey:rsa.PrivateKey) -> list:
    """
    First, tests if it's an error/end packet received\n
    returns list of form: [size, fragments]\n\n
    If no fragmentation: fragments is equal to 1\n
    Let's assume that the maxPacketSize is equal to 2048.\n
    We have a packetSize of 187 and it is not fragmented:\n
    the router will receive:\n
        0187|1\n
    returns [minus_value] if an error occured\n
    """
    nbr_of_bytes = SecureNET_do_Calculate_Nbr_of_Digits_in_maxPacketSize() + 2
    data_in = rsa.decrypt( s.recv(nbr_of_bytes), privkey ).decode()

    if( DEBUG == 1 ):
        print(f"#DEBUG func_recv_packet_size_and_seg: data_in: {data_in} #DEBUG")

    if( data_in[:3] == "0xE" ):
        return [int(data_in[4])]
    elif( data_in[:2] == "0x"):
        return [-4]


    return [int(data_in[:nbr_of_bytes-2]), int(data_in[-1])]
def SecureNET_do_Wait_for_ACK(s:socket.socket, privkey:rsa.PrivateKey) -> int:
    """
    returns 1 if received ACK\n
    returns 0 if not.
    """
    data_in = rsa.decrypt( s.recv(4), privkey ).decode()
    if( data_in == SecureNET_ACK() ):
        return 1
    else:
        return 0


# actions
def SecureNET_do_TCP_Accept_InConnection(s:socket.socket) -> tuple:
    """
    return the client_socket and the address
    """
    infos = (cli_s, address) = s.accept()
    return infos


def SecureNET_do_TCP_Send_no_frag(s:socket.socket, data:bytes, pubkey:rsa.PublicKey, privkey:rsa.PrivateKey) -> int:
    # SYN
    s.send( rsa.encrypt(SecureNET_SYN(), pubkey) )
    if(DEBUG == 1):
        print(f"#DBG Sent syn packet #DBG")
    # test if SYN ACK
    if(rsa.decrypt(s.recv(4), privkey) != SecureNET_SYN_ACK()):
        print("Did not receive SYN_ACK, exiting...")
        s.send(SecureNET_ERR_protocol_error())
        s.close()
        return -4
    # ACK
    s.send( rsa.encrypt( SecureNET_ACK(), pubkey) )
    if(DEBUG == 1):
        print(f"#DBG Sent ack packet, end of handshake #DBG")

    # send size and frag of the packet
    SecureNET_do_Send_Packet_Size_and_Segmentation(s, len(data), 1)

    # send the packet
    s.send( rsa.encrypt(data, pubkey) )
    if(DEBUG == 1):
        print(f"#DBG Sent data #DBG")
    # wait for ack reply
    if(SecureNET_do_Wait_for_ACK(s) == 1):
        print("Did not receive ACK, exiting...")
        s.send(SecureNET_ERR_protocol_error())
        s.close()
        return -4
    else:
        if( DEBUG == 1 ):
            print("Packet sent, ack received, exiting...")
        s.send(SecureNET_End_Connection())
        s.shutdown(0)
        s.close()
        return 0


def SecureNET_do_TCP_Recv(s:socket.socket, pubkey:rsa.PublicKey, privkey:rsa.PrivateKey) -> str:
    # First test the connection
    if( rsa.decrypt(s.recv(4), privkey) != SecureNET_SYN() ):
        print("Did not receive SYN, exiting...")
        s.send( rsa.encrypt(SecureNET_ERR_protocol_error(), pubkey) )
        s.close()
        return -4
    if(DEBUG == 1):
        print(f"#DBG received syn packet #DBG")

    s.send( rsa.encrypt(SecureNET_SYN_ACK(), pubkey) )
    if(DEBUG == 1):
        print(f"#DBG Sent syn ack packet #DBG")

    if( rsa.decrypt(s.recv(4), privkey) != SecureNET_ACK()):
        print("Did not receive ACK during handshake sequence, exiting...")
        s.send( rsa.encrypt(SecureNET_ERR_protocol_error(), pubkey) )
        s.close()
        return -4
    if(DEBUG == 1):
        print(f"#DBG received ack packet #DBG")


    # First, recv the packet len and segmentation
    seg_frag = SecureNET_do_Recv_Packet_Size_and_Segmentation(s)
    if(DEBUG == 1):
        print(f"#DBG received seg and frag of the next packet {seg_frag} #DBG")
    # test if no error
    if( seg_frag[0] < 0 ):
        print("Received an error or bad request in recv seg and frag, exiting...")
        s.send( rsa.encrypt(SecureNET_ERR_protocol_error(), pubkey) )
        s.close()
        return "-4"
    
    # set the bool var
    fragmented = 0
    if( seg_frag[-1] > 1 ):
        if(DEBUG == 1):
            print(f"#DBG This packet is fragmented #DBG")
        fragmented = 1
    
    # then ack it
    s.send( rsa.encrypt(SecureNET_ACK(), pubkey) )
    if(DEBUG == 1):
        print(f"#DBG Sent ACK packet #DBG")

    # recv the packet
    data_in = rsa.decrypt( s.recv(int(seg_frag[0])), privkey ).decode()
    if(DEBUG == 1):
        print(f"#DBG Received the packet #DBG")
    # test if err
    if( data_in[:3] == "0xE" ):
        print("Received an error from client, exiting...")
        s.send( rsa.encrypt(SecureNET_ERR_connection_drop_cancel(), pubkey) )
        s.close()
        return "-4"
    else:
        # ACK it
        s.send( rsa.encrypt(SecureNET_ACK(), pubkey) )
        if(DEBUG == 1):
            print(f"#DBG ACKed the packet #DBG")


        if(DEBUG == 1):
            print(f"#DBG ALRIGHT, RECEIVED THE PACKET ! #DBG")
        s.send( rsa.encrypt(SecureNET_End_Connection(), pubkey) )
        s.shutdown(0)
        s.close()
        return data_in

