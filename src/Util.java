

import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/**
 *
 * Originally by Erik Costlow, extended by Ian Welch & Wade S. Oh
 *
 */
public class Util {

    /**
     * Just for nice printing.
     *
     * @param bytes
     * @return A nicely formatted byte string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /**
     * Convert a string as hex.
     *
     * @param s the string to be decoded as UTF-8
     */
    public static String strToHex(String s) {
        s = "failed decoding";
        try{
            s = Util.bytesToHex(s.getBytes("UTF-8"));
        }catch(UnsupportedEncodingException e) {
            System.out.println("Unsupported Encoding Exception");
        }
        return s;
    }


    /**
     * Encrypts plain text with public key
     *
     * @param plaintext string plain text
     * @param publicKey used to encrypt plaintext
     * @return ciphertext as byte array
     */
    static byte[] encrypt(byte[] plaintext, PublicKey publicKey) {
        try{
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(plaintext);

            System.out.println("Successfully encrypted message.. \nplain: " + Arrays.toString(plaintext) + "\ncipher: " + Arrays.toString(encrypted));
            System.out.println("-----------------------------------------------------------------------------------------------");
            return encrypted;
        }catch(Exception e) {
            System.out.println("Error found during encryption: " + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypts ciphertext using private key
     *
     * @param ciphertext
     * @param privateKey
     * @return plaintext as byte array
     * @throws Exception
     */
    static byte[] decrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        try{
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decrypted = decryptCipher.doFinal(ciphertext);
            System.out.println("Successfully decrypted message.. \n" + "cipher: " + Arrays.toString(ciphertext) + "\nplain: " + Arrays.toString(decrypted));
            System.out.println("-----------------------------------------------------------------------------------------------");
            return decrypted;

        }catch(Exception e) {
            System.out.println("Error found during decryption " + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }

    }

    /**
     * Signs message
     * @param ciphertext
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        try{
            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(ciphertext);

            return privateSignature.sign();
        }catch(Exception e) {
            System.out.println("Error found adding signature to the message." + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Combines encrypted message with signature
     * @param msg
     * @param dst
     * @param kp
     * @return
     * @throws Exception
     */
    public static byte[] addSignature(byte[] msg, PublicKey dst, KeyPair kp) throws Exception {
        try{
            byte[] encrypted =  encrypt(msg, dst);
            byte[] signed = sign(encrypted, kp.getPrivate());
            byte [] encryptedSigned = new byte [encrypted.length + signed.length];

            System.arraycopy(encrypted, 0, encryptedSigned, 0, encrypted.length);
            System.arraycopy(signed, 0, encryptedSigned, encrypted.length, signed.length);

            return  encryptedSigned;
        }catch(Exception e) {
            System.out.println("Error found adding signature to the message." + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Verifies that signature is correct
     *
     * @param msg
     * @param sign
     * @param pk
     * @return
     */
    public static boolean verify(byte[] msg, byte[] sign, PublicKey pk) {
        try{
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(pk);
            signature.update(msg);

            return signature.verify(sign);
        } catch (Exception e) {
            System.out.println("Error found during verification." + "\n" + "Disconnecting..");
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Decrypt and verify data
     * @param numBytes
     * @param msg
     * @param dst
     * @param kp
     * @return
     * @throws Exception
     */
    public static byte[] verifyAndDecrypt(int numBytes, byte[] msg, PublicKey dst, KeyPair kp) throws Exception {
        try{
            // decrypt data
            byte[] signature = new byte[256];
            byte[] cipherText = new byte[numBytes - 256];

            System.arraycopy(msg, 0, cipherText, 0, numBytes - 256);
            System.arraycopy(msg, cipherText.length, signature , 0, signature.length);

            //verify
            if (!(Util.verify(cipherText,signature, dst))) throw new InvalidKeyException();

            return decrypt(cipherText, kp.getPrivate());
        }catch(Exception e) {
            System.out.println("Error found during verification and decryption." + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Gets a public private key pair from the keystore
     * @return Public private key pair
     * @throws Exception
     * https://niels.nu/blog/2016/java-rsa
     */
    public static KeyPair getKeyPairFromKeyStore(String password, String alias) throws Exception {
        try{
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("src/part2/cybr372.jks"), password.toCharArray());   //Keystore password
            KeyStore.PasswordProtection keyPassword =
                    //Key password
                    new KeyStore.PasswordProtection(password.toCharArray());

            KeyStore.PrivateKeyEntry privateKeyEntry = (
                    KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, keyPassword);

            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();

            return new KeyPair(publicKey, privateKey);
        }catch(Exception e) {
            System.out.println("Error found getting key from key store." + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Generates a random AES 128 master key
     * @return master key
     * @throws Exception
     */
    public static SecretKey getMasterKey(String algorithm) throws Exception {
        try{
            SecretKey masterkey;

            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            SecureRandom random = new SecureRandom();
            keyGen.init(128, random);
            masterkey = keyGen.generateKey();

            return masterkey;

        }catch(Exception e) {
            System.out.println("Error found getting key from key store." + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        return nonce;
    }

    /**
     * Derive another key from the given master key
     *
     * @param masterKey      to be used as the base for building new key
     * @param text      text added to generate new key
     * @return  new key
     * @throws Exception
     */
    public static SecretKey getAESKey(SecretKey masterKey, String text) {
        try{
            // derive AES key from master key
            String mk = Base64.getEncoder().encodeToString(masterKey.getEncoded());
            String nk = mk + text;

            // decode the base64 encoded string
            //byte[] decodedKey = Base64.getDecoder().decode(s);
            byte[] decodedKey = nk.getBytes();

            // rebuild key using SecretKeySpec
            SecretKey key = new SecretKeySpec(decodedKey, "AES");

            return key;
        }catch(Exception e) {
            System.out.println("Error found generating AES key." + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] joinByteArray(byte[] byte1, byte[] byte2) {

        return ByteBuffer.allocate(byte1.length + byte2.length)
                .put(byte1)
                .put(byte2)
                .array();

    }

    /**
     * Encrypt a plaintext with given key.
     *
     * @param plaintext      to encrypt (utf-8 encoding will be used)
     * @param secretKey      to encrypt, must be AES type
     * @return encrypted message
     * @throws Exception
     */
    public static byte[] AESGCMEncrypt(String plaintext, SecretKey secretKey) throws Exception {
        try{
            // Get Cipher Instance for selected algorithm
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            // Create SecretKeySpec for key
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

            // Create NONCE for each session
            byte[] nonce = generateNonce();
            byte[] data = plaintext.getBytes();

            System.out.println("NONCE used for encryption: " + bytesToHex(nonce));
            // Create GCMParameterSpec for key
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);

            // Initialize Cipher for ENCRYPT_MODE for encrypt plaintext
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

            // attach AAD
            byte[] metaData = "part3".getBytes(StandardCharsets.UTF_8); //meta data you want to verify with the secret message

            // Perform Encryption
            //cipher.updateAAD(metaData);
            byte[] cipherText = cipher.doFinal(data);

            //System.out.println(cipherText.length);
            //System.out.println(bytesToHex(cipherText));

            byte[] load = joinByteArray(nonce, cipherText);
            //cipherText = joinByteArray(load, metaData);
            System.out.println("Successfully encrypted message.. \nplain: " + bytesToHex(plaintext.getBytes()) + "\ncipher: " + bytesToHex(load));
            System.out.println("-----------------------------------------------------------------------------------------------");

            return load;
        }catch(Exception e) {
            System.out.println("Error found during AES GCM encryption" + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] addPadding(byte[] data) {
        byte[] padded = new byte[32];

        for(int i = 0; i < padded.length; i++) {

            if(i < data.length) {
                padded[i] = data[i];
            }else {
                padded[i] = 0;
            }
        }
        return padded;
    }

    /**
     * Decrypts encrypted message.
     *
     * @param cipherText iv with ciphertext
     * @param secretKey      used to decrypt
     * @return original plaintext
     * @throws Exception if anything goes wrong
     */
    public static String AESGCMDecrypt(byte[] cipherText, SecretKey secretKey) throws Exception {
        try{
            // Get Cipher Instance based on selective AES algorithm
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            // Create SecretKeySpec for key
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

            // Retrieve NONCE from the cipher block
            byte[] nonce = Arrays.copyOfRange(cipherText, 0, 12);
            byte[] data = erasePadding(Arrays.copyOfRange(cipherText, 12, 48));
            //byte[] metaData = Arrays.copyOfRange(cipherText, 48, cipherText.length);

            System.out.println("NONCE used for decryption: " + bytesToHex(nonce));
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);

            // Initialize Cipher for DECRYPT_MODE to in plain text
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

            // Perform Decryption on encrypted text
            System.out.println(bytesToHex(data));
            //cipher.updateAAD(metaData);
            byte[] decryptedText = cipher.doFinal(data);
            System.out.println("Successfully encrypted message.. \ncipher: " + bytesToHex(cipherText) + "\nplain: " + bytesToHex(decryptedText));
            System.out.println("-----------------------------------------------------------------------------------------------");

            return new String(decryptedText);
        }catch(Exception e) {
            System.out.println("Error found during AES GCM decryption." + "\n" + "Disconnecting..");
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] erasePadding(byte[] padded) {
        int count = 0;

        for(int i = 0; i < padded.length; i++) {
            if(padded[i] == 0) {
                count++;
            }
        }

        byte[] data = new byte[padded.length - count];

        for(int i = 0; i < data.length; i++) {
            data[i] = padded[i];
        }
        return data;
    }
}

