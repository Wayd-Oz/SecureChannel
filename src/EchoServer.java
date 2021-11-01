

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private KeyPair kp;
    private PublicKey dest;

    private static int messageID = 0;

    private static SecretKey masterKey;

    private static SecretKey clientToServerAESKey;
    private static SecretKey serverToClientAESKey;


    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) {
        try {
            messageID++;

            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            byte[] data = new byte[2048];

            // retrieve master key
            System.out.println("Received master key from client..");
            byte[] dec = Util.verifyAndDecrypt(in.read(data), data, dest, kp);
            masterKey = new SecretKeySpec(dec, 0, dec.length, "AES");
            System.out.println("*****");
            System.out.println("Generated master key.\n" + masterKey);
            System.out.println("*****");
            //String mk = new String(dec, StandardCharsets.UTF_8);

            // encrypt and sign key
            byte[] encryptedSigned = Util.addSignature(dec, dest, kp);

            // send verification
            System.out.println("Sending master key back to client for verification.\n" + Util.bytesToHex(dec));
            out.write(encryptedSigned);
            out.flush();
            System.out.println("-----------------------------------------------------------------------------------------------");

            clientToServerAESKey = Util.getAESKey(masterKey, "toserver");
            serverToClientAESKey = Util.getAESKey(masterKey, "toclient");
            System.out.println("*****");
            System.out.println("Generated AES key.");
            System.out.println("Client to server:\n" + clientToServerAESKey);
            System.out.println("Server to client:\n" + serverToClientAESKey);
            System.out.println("*****");
            //SecretKey secretKey = new SecretKeySpec(AESKey.getEncoded() , "AES");

            int numBytes;
            data = new byte[2048];

            while ((numBytes = in.read(data)) != -1) {
                // send message ID as nonce for authentication through meta data

                String decrypted = Util.AESGCMDecrypt(data, clientToServerAESKey);
                System.out.println("Received plaintext from client \n" + decrypted);

                // encrypt response (this is just the decrypted data re-encrypted)
                byte[] cipherText = Util.AESGCMEncrypt(decrypted, serverToClientAESKey);
                System.out.println("Sending ciphertext to client \n" + Util.bytesToHex(cipherText));

                out.write(cipherText);
                out.flush();
                System.out.println("--------------------------------------------------------------------------------------");
            }
            stop();
        } catch (IOException | InvalidKeyException e) {
            System.out.println(e.getMessage());
        } catch (Exception e) {
            System.out.println(e.getClass() + "Error found processing requests..");
            e.printStackTrace();
        }

    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void main(String[] args) throws Exception {
        if(args[0].equals("password")) {
            EchoServer server = new EchoServer();
            server.kp = Util.getKeyPairFromKeyStore(args[0], "server_cert");
            server.dest = Util.getKeyPairFromKeyStore(args[0], "client_cert").getPublic();
            server.start(4444);
        }else {
            System.out.println("Incorrect password.\n" + "Failed to access key store.");
        }
    }

}



