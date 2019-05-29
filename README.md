# CS330---Computer-Networking-Chat-application-with-RSA-and-AES-hybrid-security-setup
A repository for the my chat web application project for the CS330: Computer Networking course at Illinois Wesleyan University

This project is a Java socket based chatting application that uses a combination of RSA and AES encryption schemes for secure transfer of
messages between the client and server. When a new client attempts to connect to the server to communicate, the client generates a pair of RSA
keys so that the AES key generated server-side for the connection may be encoded for safe passing between the client and server.

The RSA keys are used to encode and later decode the server's AES key so that, in the end, both the client and the server have the AES key 
and can communicate using AES-encrypted messages.
