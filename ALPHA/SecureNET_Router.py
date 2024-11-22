import socket
import SecureNET_proto

local_bind_addr = socket.gethostname()
local_bind_port = int(input("Please, enter the port\n(be careful, you might need to open/forward ports on your ISP router)"))

dist_router_ip = input("\nPlease, enter the IP address of a router: ")
dist_router_port = int(input("Please, enter the Port of the router: "))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind( (local_bind_addr, local_bind_port) )

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# testing
choice = int(input("Cli/Serv: 1/2 : "))

if(choice == 1):
    c.connect((dist_router_ip, dist_router_port))
    print(SecureNET_proto.SecureNET_do_TCP_Send_no_frag(c, "Test!".encode()))
else:
    s.listen(1)
    cli_sock, addr = SecureNET_proto.SecureNET_do_TCP_Accept_InConnection(s)
    print(SecureNET_proto.SecureNET_do_TCP_Recv(cli_sock))


"""
run = 1
accepted_clients = 0
cli_list = []
while( run ):
    if( accepted_clients == 5 ):
        s.listen(5)
        accepted_clients = 0
        print("reseted listen socket")
    else:
        cli_list.append(SecureNET_proto.SecureNET_do_TCP_Accept_InConnection(s))
        # Threaded call, to do...
        accepted_clients += 1
        print(f"We accepted a new connection, con n°{accepted_clients}")
        SecureNET_proto.SecureNET_do_TCP_Run_Server_Socket(cli_list[-1])
"""


print("Alright, it's over :D")