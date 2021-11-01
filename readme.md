# Secure Channel

## Information
    Ensuring a secure channel between Echo-client and Echo-server.

#### Functions
      - Client chooses a random AES 128-bit master key and sends it to the server.
      - Server sends the received key back to the client to indicate that this is the master key to be used for the session.
      - Generates different client-server and server-client keys used with the AES-GCM cipher.
      - Uses block cipher mode that combines encryption and authentication (AES-GCM).
      - EchoClient.sendMessage() supports messages between 1 and 32 characters long.

#### To run
     - First, start up the server by compiling and running EchoServer.java with a single argument parameter “badpassword” as the code to access the keystore.
     - Then compile and run EchoClient.java also with the same single argument parameter “password”.

#### Design
     - Secure data handling – using byte arrays rather than strings and all communications between client and server are encrypted.
     - Isolate errors using try-catch exception blocks on each functionality.
