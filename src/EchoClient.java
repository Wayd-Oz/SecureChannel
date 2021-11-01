

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    private static int messageID = 0;

    // generate master key
    private static SecretKey masterkey;
    // generate AES key
    private static SecretKey clientToServerAESKey;
    private static SecretKey serverToClientAESKey;

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error found when initializing connection..");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     //* @param msg the message to send
     */
    public String sendMessage(String msg) {
        try {
            // support up to 32 characters
            if(msg.length() <= 32) {
                messageID++;
                // read, encrypt and sign data
                //byte[] data = msg.getBytes(StandardCharsets.UTF_8);
                clientToServerAESKey = Util.getAESKey(masterkey, "toserver");
                serverToClientAESKey = Util.getAESKey(masterkey, "toclient");
                System.out.println("*****");
                System.out.println("Generated AES key.");
                System.out.println("Client to server:\n" + clientToServerAESKey);
                System.out.println("Server to client:\n" + serverToClientAESKey);
                System.out.println("*****");

                //SecretKey secretKey = new SecretKeySpec(AESKey.getEncoded(), "AES");

                //byte[] nonce = String.valueOf(messageID).getBytes(StandardCharsets.UTF_8); //meta data you want to verify with the secret message

                byte[] cipherText = Util.AESGCMEncrypt(msg, clientToServerAESKey);

                // send data
                System.out.println("Sending ciphertext to server\n" + Util.bytesToHex(cipherText));
                out.write(cipherText);
                out.flush();

                //byte[] response = new byte[1024];
                //int numBytes;
                //while ((numBytes = in.read(response)) != -1) {
                ////byte[] response = new byte[1024];
                ////in.read(response);

                // Decrypt data
                //byte[] decrypted = part3.Util.verifyAndDecrypt(numBytes, response, dest, kp);
                //String msgDecrypted = new String(decrypted, StandardCharsets.UTF_8);
                //System.out.println("Received plaintext from server" + msgDecrypted);
                //System.out.println("--------------------------------------------------------------------------------------");

                //return msgDecrypted;
                //}
                return null;
            }else {
                System.out.println("SendMessage can only support up to 32 characters long.\n" + "Disconnecting..");
                return null;
            }

        } catch (Exception e) {
            System.out.println(e.getMessage() + ": Error found during communication with the server" + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    public String sendMasterKey(SecretKey masterKey, KeyPair kp, PublicKey dest) throws Exception {
        try {
            System.out.println("*****");
            System.out.println("Generated master key.\n" + masterKey);
            System.out.println("*****");

            // read, encrypt and sign key
            byte[] mk = masterKey.getEncoded();
            byte[] encryptedSigned = Util.addSignature(mk, dest, kp);

            // send data
            System.out.println("Sending master key to server\n" + Util.bytesToHex(mk));
            out.write(encryptedSigned);
            out.flush();
            System.out.println("-----------------------------------------------------------------------------------------------");

            // receive master key verification message from server
            byte[] verification = new byte[1024];
            int numBytes;
            while ((numBytes = in.read(verification)) != -1) {
                System.out.println("Message received from server.. decrypting..");

                // Decrypt data
                byte[] decrypted = Util.verifyAndDecrypt(numBytes, verification, dest, kp);
                //String msgDecrypted = new String(decrypted, StandardCharsets.UTF_8);
                String key = Util.bytesToHex(decrypted);
                System.out.println("Received master key verification from server.\n" + key);
                System.out.println("-----------------------------------------------------------------------------------------------");

                return key;
            }
            return null;
        }catch (Exception e) {
            System.out.println(e.getMessage() + ": Error found sending master key to server" + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("Error found closing the program..");
        }
    }



    public static void main(String[] args) throws Exception {
        if(args[0].equals("password")) {
            KeyPair kp;
            PublicKey dest;

            EchoClient client = new EchoClient();
            kp = Util.getKeyPairFromKeyStore(args[0], "client_cert");
            dest = Util.getKeyPairFromKeyStore(args[0], "server_cert").getPublic();
            client.startConnection("127.0.0.1", 4444);

            // generate master key and send it to server
            masterkey = Util.getMasterKey(ALGORITHM);
            client.sendMasterKey(masterkey, kp, dest);

            client.sendMessage("testing123");

            //client.sendMessage("12345678");
            //client.sendMessage("ABCDEFGH");
            //client.sendMessage("87654321");
            //client.sendMessage("HGFEDCBA");

            client.stopConnection();
        }else {
            System.out.println("Incorrect password.\n" + "Failed to access key store.");
        }
    }
}
