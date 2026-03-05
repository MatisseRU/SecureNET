# Introduction 

Every machines part of the SecureNET's hidden network are called SNET Routers.

A software is designed to run the SNET Routers following this technical specification.


# SecureNET's Topology and abstract definitions

- In order to keep track of everything (guaranteeing non-repudiation), SNET routers exchange every routing/maintenance/administrative informations through a blockchaining system.

- End-users' traffic is "proxied" through the SNET router program.

- Packets are of fixed size with padding included if necessary.

- Every connection is initialized with asymmetric cryptography (I.E. RSA) and then cyphered using symmetric cryptography (I.E. AES-512).

- SNET participants are tracked using certificates containing: IPv4 / IPv6 addresses or DNS names, date of creation and date of expiration, Public Key (I.E. RSA), Admin's signed approbation (I.E. RSA hash signature), Certificate's footprint (I.E. SHA-512 Hash).  
Every certificates are stored to the blockchain thus permitting integrity,  authenticity and non-repudiation.

- Certificates should expire quickly.

- If the admin is not online, delegation can be implemented.

- End-users' data must travel either through point-to-point or by broadcasting (defined by the Admin).

- The protocol sends public-key signed data, after cryptographic initialization process mentionned above, of course, guaranteeing integrity and authenticity.

- The path of end-user data is calculated using BGP-like protocol (local pref, trust, etc...).

- By default, end-user data must pass through 3 routers.

- The admin can set up a specific timeout between 2 SNET communications (preventing time-based privacy compromission) by default it should be set to 500ms, in ideal, it must be calculated using the lowest bandwidth measured in the SNET network.

- Packet headers are fixed in size.

- Packet header contains: SNET Routing Address, Public-key signed footprint

- Packet header is individualy crypted using the SNET Router's public key (destination), every headers are "rolled-over" after it has been treated.

- This packet header accumulation is free in sizing.

