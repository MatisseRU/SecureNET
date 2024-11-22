# SecureNET
Simple tcp/udp hidden network protocol inspired by Tor and I2P


All of the computers constituting the network are called "routers".

A software is designed to run the router.


The IP address becomes a Hop-to-Hop layer, just like mac addresses in the OSI model.

So, we can draw a new model on which this networking technology stands:


    - Layer 1: Physical: wire
    
    - Layer 2: Data Link: mac address
    
    - Layer 3: Network: IP address
    
    - Layer 4: Transport -> UDP (peer-to-peer)
    
    NEW LAYERS IMPLEMENTED:
    
    - Layer 5: Spark Routing Protocol
    
    - Layer 6: Encrypted Data
    


Clearly resumed:

    - Layer 1+2+3+4 -> "support" on which the network rely
    
    - Layer 5 -> End-to-End Delivery
    
    - Layer 6 -> Data.
    



You have 2 "modes" to chose when creating or administrating the Secure Network:

0: Security Oriented: Only broadcasting. No Spark Addresses. No network mapping, only host discovery like in I2P.

1: Performance Oriented: the whole protocols explained in this documentation.








## I.) What the heck is SRP ? ##

Service and router discovery is a main component of SRP.

2 Actions occur on a SRP based network:

    1) When someone offers a service (such as a Web Site...) it broadcasts a service descriptor using the blockchain, it contains:
    
            - Protocol Header
            
            - date of expiry of the service descriptor (and the addresses featured)
            
            - meeting addresses (comparable to .onions provided by Tor or .i2p provided by I2P, but "direct" access, using relays).
            
            - ADDITIONAL (not necessary): cryptographic protocol used to encrypt the data shared (ex: RSA, TLS, SSL, etc...)
            
            - service protocol used (HTTP ; FTP ; SMTP ; etc... or even custom protocols)
            
            - hash of the service descriptor (meeting points, cp and sp hashed up)

            

    -> This is called "ionization".


    2) The interested clients just have to connect to the server by using one of the addresses provided by the service provider.



NOTE: YOU NEVER EVER DIRECTLY COMMUNICATE DIRECTLY TO ANY ROUTER, NEVER EVER, YOU ARE ONLY ABLE TO USE SPARKRYPT ADDRESSES.

DIRECT OR "SINGLE HOP" IS ONLY HAPPENNING WHEN THE ROUTERS DO ROUTING AND PROTOCOL RELATED ACTIONS, HOWEVER, THE USER

CAN'T COMMUNICATE DIRECTLY TO OTHER PEOPLE.

    
        Client's packet content:

        
            - Protocol Header (op-codes and routing related data)
            
            - reply header (same header used to send the packet but built backwards, or a custom one for security/reliability reasons.)
            
            - hash of the service

            

    -> A client connection request is called a "Spark"











## II.) How do packets travel anonymously ? ##


NOTE: The path the packet must take is defined by the author of the packet, more precisely by the router or the user himself.


Here is the skeleton of a packet:




@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


    @@@@@@@ 1) HEADER: ENCRYPTED USING SPARKRYPT ENCRYPTION @@@@@@@

    
        NOTE: relay router's private key is used to uncrypt the necessary infos.

        
        - op-codes used to determine which action the router must perform / determine the type of the packet.
        
        - operation/routing related data
        
        NOTE: This part is Sparkrypt encrypted by the sender using the protocol
        
              explained in part III, it means that this section that the necessary infos can only be
              
              decrypted by the right router, so nobody can determine the actual path of that packet
              
              and so privacy is still applied. Nobody knows who is the sender nor the destination
              
              even the adjacent relays (first and last relay), because they do not even know
              
              that they actually are those first and last relays, unlike Tor.
              
              The router will decrypt the infos using its private key.
              
              The header is "rolled over", this means that the router will append at the end of the
              
              header the infos meant to him and delete from the beginning of the header the infos it read:
              

              Header at hop 1: [hop1][hop2][hop3]...[hopX] -> The first relay decrypts [hop1] and processes
              
              it, then append it to the end of the header (the encrypted version, obviously).
              
              Header at hop 2: [hop2][hop3]...[hopX][hop1]

              

              Using this technique, nobody can determine the length of the packet's path, nor the relay's
              
              place in the chain. The length of the header is predetermined and filled up with "garbage"
              
              to fit the actual size so nobody can determine the path used by calculating the lenght of
              
              the header and the amount of space used to encode processed infos.

              

#################################################



    @@@@@@@ 2) REPLY HEADER: SPARKRYPT ENCRYPTED DATA @@@@@@@

    
        - reply header (the header the endpoint router, as an example: the service provider, must use)




#################################################



    @@@@@@@ 3) ENCRYPTED USING ENPOINT ROUTER's PUBLIC KEY @@@@@@@
        
        
        - Data shared



@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@








## III.) About network's transparency and privacy garentee from the routing protocol  ##


    NOTE: Each router can't determine what the next one will do nor what the previous one did
    
          due to encapsulation provided by Sparkrypt packet encryption.
          
          For instance, the sender wants to use router A and B as "relays" and router C as the exit to the clear-net
          
          or to another network (ex: tor...), the packet is composed of an header determining which action has to be
          
          performed by each router, and a data section (the actual data securely transmitted).

          

Here is how the sender creates the header:


    1) Write in the header the infos used to tell router C to forward this packet outside of the network,
    
       encrypt it using C router's public key

       
    2) Append at the beginning of the header the op-code telling router B to forward the packet to router C,
    
       encrypt it using B router's pub key

       
    3) Append at the beginning of the header the op-code telling router A to forward the packet to router B,
    
       encrypt it using A router's pub key

       
    4) Append the data to be transfered at the end of the packet.

    
    5) Finaly, send the packet to Router A.

    

The user creates the reply header by doing the same procedure but beginning from step 3 and going all along to step 1. (if the same path is used, otherwise you can use another path using other routers)


By the way, this network model wasn't firstly made for cross-networking purposes, rather as a mean to securely and

anonymously share data and hide the actual connection's route so nobody can determine that a communication took place between

a person A and a person B when participating in the Secure Network.




This is version v1.0 so, even if i thought about implementing cross-networking, this model wasn't meant

to see cross-networking implementation at the beginning of the project, yet to find an interesting compromise

between Tor and I2P on which browsing is so much painful.

I also thought about taking it into production line in enterprises, personal networks or even LARGE networks such as over the

internet (the same way Tor and I2P are world wide implemented).



It's a model, not a network itself for now..., i wish it would be implemented as a world wide hidden network like the Tor and I2P projects.

It is also meant to be modified and very modular, like a protocol would.


This is a FREE and OPEN SOURCE project, for commercial/business purpose contact me, feel free to use it as you wish. For commercial purposes contact me.






            >> And please credit me when you use it on your own, thanks :D <<








## IV.) About data encryption and cryptographic liberty ##


The service providers/users are free to choose a kind of cryptographic security over the data already encrypted

with the router's public key, so that they can wrap the data shared in an additional layer of security,

i recommend people to use generic cryptographic algorithm such as RSA, TLS, SSL or even AES and somehow share the symetric key,

but basically, use mainstream and well known cryptographic algorithms known as secure enough, rather than "home-made"

algorithms, unless you know what you are doing. ;)











## V.) What the heck is SMP (Spark Map Protocol) and how the blockchain travels ##


As mentioned earlier, the whole network is mapped, this means that any router connected to the Secure Network

knows who is connected to it and who used to be. Oh, you might think: "This is shooting yourself in your foot! this is not secured

and anyone who wish to, for some reasons, shut off the whole "hidden" network just has to get into it and shut off or ban the computers

runing it!"



Well.... yep. However, you have to get into the network first ! If your network is totally private, only attacks such as "man in the middle"

might do the work to detect anormal traffic, but if you have hundreds or THOUSANDS of machines.... ehhhh good luck attacker.

However you're totally fine as a participant of the Secure Network, since nobody can check what is happening on the network.




Mapping the network for every routers to be able to effectively get the whole list of participants is achieved by using a blockchain.




    1.) Structure and content of the blockchain
    
        -Genesis Block: The Very First Members of the Secure Network.
        
	    -> In the Genesis Block is stored the very first routers' IP addresses and their public key.
     
            -> In this block is refered all the network informations and options.
            
        -Next Blocks: Containing new routers (new participants of the network), new services, special broadcast messages (yes, broadcasting is implemented as a way of communication! for administrative purposes).

        

    2.) Structure and content of a block
    
        -Hash of the block
        
        -Title of the block (Tells if it's a new client, a new service, or an administrative broadcast message.)
        
        -Date and Time
        
        -Content
        
        -Hash of the previous block
        

	>>Structure of a new client block
 
        -Hash of the block
        
        -Title
        
        -Date and Time
        
        -new router's IP address
        
        -new router's public key
        
        -new router's default Sparkrypt Addresses (i'll explain later)
        
        -Hash of the previous block
        

    >>Structure of a new service block
    
        -Hash of the block
        
        -Title
        
        -Date and Time
        
        -service descriptor (mentionned in part I.).
        
        -Hash of the previous block
        

    >>Structure of a broadcast message
    
        -Hash of the block
        
        -Title
        
        -Date and Time
        
        -Flag (administrative, informative, emergency, traffic/routing-related...)
        
        -Message
        
        -Hash of the previous block

        



Different actions in the mapping protocol:


1.) When someone wants to join the Secure Network, it firstly needs to be approved by one of the routers (one of the participants).

This router, which accepted the newbie, can:

    -send a broadcast message to ask everyone if this new guy is trustworthy
    
    -directly give a copy of the blockchain and broadcast a message that a new participant has joined the Secure Network.
    
    -> when the router broadcasts the "ask everyone ... trustworthy" it waits until 51% of online routers accept that the newbie joins.
    

2.) When the network is already established and working, routers keep asking every single participants if they are still online, the time lapse is totally free to choose

    -router A asks router B if he is alive
    
    -case 1: router B responds, router A in return doesn't do anything and moves to the next one.
    
    -case 2: router B doesn't respond or the packet dropped, in that case, router A adds a new block to the blockchain.
    
    The block will contain the broadcast message telling that router B seemed dead or inactive or simply disconnected.
    


3.) Blockchained message ? or regular broadcasting ?

Routers can communicate using 2 different ways: by broadcasting to everyone or by directly unicasting.


    -> Broadcasting: 2 ways of broadcasting:

    
        -standard broadcasting
        
        -block pushing into the blockchain
        

Broadcasting meant to map the network and keep track of every events occuring inside the network or that simply needs to be stored to prevent any
parasiting broadcasting such as "re-asking", is performed with the blockchain.

Broadcasting meant to only ask or share information that doesn't need to be shared again or asked back by anyone is broadcasted "standardly".

No blockchain involved.





############################ SUM UP ##############################


    2 Modes:
    
        - Security Oriented
        
        - Performance Oriented
        


    1.) Network topology
    
    - UDP Connections
    
    - routers.
    
    - 3 ways of communication: broadcasting, unicasting, Spark Routing
    
    - 2 ways of broadcasting: regular broadcasting and blockchain sharing
    
        -> Broadcasting is achieved by unicasting to everyone in v1.0
        
        -> The way the blockchain is updated is called propagation in v1.0

        
    NOTE: ROUTERS ARE ABLE TO UNICAST ONLY IN A MANNER OF NETWORK MAINTENANCE/ADMINISTRATION.



    2.) Spark Mapping Protocol
    
    - Network mapping:
    
        -> Newbie joins if the router requested (and 51% of online routers) accept(s) him (the second part can be disabled)
        
        -> Routers request every other routers if they are online, if not, they broadcast using the blockchain. (time lapse can be sat up)

        

    3.) Spark Routing Protocol
    
    - When someone offers a service, he broadcasts a service descriptor through the blockchain.
    
    - When some clients want to share data (basic usage of a network lol) they ONLY use Sparkrypt Addresses. No direct and "unicast" connection.
    
    - When a client or a server has to reply to another, they use the reply header given by the guy they are talking to.

    

##################################################################





FEATURES OF v1.0:

-Spark Map Protocol

-Spark Routing Protocol

-Secured Administrative Share System (blockchain)

-Auto search viable ports (if uPnp is blocked or any other peer-to-peer ports are blocked, this feature will find any unused ports and use it)



>> User Feature:

-Support of every browser thanks to Proxying (like I2P)

-Support of client/server communication

-Private Messaging


FEATURES OF v2.0:

-Torrenting

-Support of Imap, Pop and SMTP for emailing

-"Exit nodes" in order to access the Clear Web

-"Bridge nodes" in order to access other networks (such as Tor or I2P)









