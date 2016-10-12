package com.example.jj.hw;

/**
 * Created by tom.stinson on 9/2/2015.
 * mods for server side on 9/3/2015
 */

// import android.util.Log; --> for android implementations

// import org.apache.commons.codec.binary.Hex;
import org.spongycastle.jce.provider.BouncyCastleProvider;
// import org.spongycastle.util.encoders.HexEncoder;

import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import com.example.jj.hw.HexEncoder;

import android.util.Base64;


public class BaseCrypto {
    //for server side
    private static final Logger LOGGER = Logger.getLogger(BaseCrypto.class.getName());


    public static final String PROVIDER = "BC";
    public static final int SALT_LENGTH = 20;
    public static final int IV_LENGTH = 16;
    public static final int PBE_ITERATION_COUNT = 100;

    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    private static final String HASH_ALGORITHM = "SHA-512";
    private static final String PBE_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "AES";

    public BaseCrypto(){
        //for server side
        Security.addProvider(new BouncyCastleProvider());
    }

    public class CryptoException extends Exception {
        public CryptoException(String msg, Exception e) {
            super(msg+": "+e.getMessage());
        }
    }

    public String encrypt(SecretKey secret, String cleartext) throws CryptoException {
        try {
            byte[] iv = generateIv();
            String ivHex = HexEncoder.toHex(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
            byte[] encryptedText = encryptionCipher.doFinal(cleartext.getBytes("UTF-8"));
            String encryptedHex = HexEncoder.toHex(encryptedText);

            return ivHex + encryptedHex;
        } catch (Exception e) {
            throw new CryptoException("Unable to encrypt", e);
        }
    }

    public String decrypt(SecretKey secret, String encrypted) throws CryptoException {
        try {
            Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
            String ivHex = encrypted.substring(0, IV_LENGTH * 2);
            String encryptedHex = encrypted.substring(IV_LENGTH * 2);
            IvParameterSpec ivspec = new IvParameterSpec(HexEncoder.toByte(ivHex));
            decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);

            byte[] decryptedText = decryptionCipher.doFinal(HexEncoder.toByte(encryptedHex));
            String decrypted = new String(decryptedText, "UTF-8");
            return decrypted;
        } catch (Exception e) {
            throw new CryptoException("Unable to decrypt", e);
        }
    }

    public SecretKey getSecretKey(String password, String salt) throws CryptoException {
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), HexEncoder.toByte(salt), PBE_ITERATION_COUNT, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM, PROVIDER);
            SecretKey tmp = factory.generateSecret(pbeKeySpec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), SECRET_KEY_ALGORITHM);
            return secret;
        } catch (Exception e) {
            throw new CryptoException("Unable to get secret key", e);
        }
    }

    private byte[] generateIv() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }

    public String encryptContent(String content, String def_pass, String salt) {
        String encryptedContent = null;
        try {
            SecretKey key = this.getSecretKey(def_pass, salt);
            encryptedContent = this.encrypt(key, content);

        } catch (BaseCrypto.CryptoException e) {
            // Log.e("encryptContent", "encryptContent CryptoException: " + e.getMessage());
            LOGGER.log(Level.SEVERE, "encryptContent CryptoException: ", e.getMessage() );

        }
        return encryptedContent;
    }

    public String decryptContent(String cryptedContent, String def_pass, String salt) {
        String content = null;
        try {
            SecretKey key = this.getSecretKey(def_pass, salt);
            content = this.decrypt(key, cryptedContent);
        } catch (BaseCrypto.CryptoException e) {
            // Log.e("decryptContent", "decryptContent CryptoException: "+ e.getMessage());
            LOGGER.log(Level.SEVERE, "decryptContent CryptoException: ", e.getMessage() );
        }
        return content;
    }
}


/*
    public String encrypt(SecretKey secret, byte[] stream) throws CryptoException {
        try {
            byte[] iv = generateIv();
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
            byte[] encrypted = encryptionCipher.doFinal(stream);
            byte[] combined = new byte[iv.length + stream.length];

            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, stream.length);
            return Base64.encodeToString(combined, Base64.DEFAULT);
        } catch (Exception e) {
            throw new CryptoException("Unable to encrypt", e);
        }
    }

    public byte[] decryptBytes(SecretKey secret, String encrypted) throws CryptoException {
        try {
            Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
            String ivHex = encrypted.substring(0, IV_LENGTH * 2);
            String encryptedHex = encrypted.substring(IV_LENGTH * 2);
            IvParameterSpec ivspec = new IvParameterSpec(HexEncoder.toByte(ivHex));
            decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);

            byte[] decryptedText = decryptionCipher.doFinal(HexEncoder.toByte(encryptedHex));
            return decryptedText;
        } catch (Exception e) {
            throw new CryptoException("Unable to decrypt", e);
        }
    }

    public String getHash(String password, String salt) throws CryptoException {
        try {
            String input = password + salt;
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM, PROVIDER);
            byte[] out = md.digest(input.getBytes("UTF-8"));
            // return HexEncoder.toHex(out);
            return Base64.encodeToString(out, 16);
        } catch (Exception e) {
            throw new CryptoException("Unable to get hash", e);
        }
    }

    public String generateSalt() throws CryptoException {
        try {
            SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
            byte[] salt = new byte[SALT_LENGTH];
            random.nextBytes(salt);
            // String saltHex = HexEncoder.toHex(salt);
            String saltHex = Base64.encodeToString(salt, 16);
            return saltHex;
        } catch (Exception e) {
            throw new CryptoException("Unable to generate salt", e);
        }
    }

    public byte[] decryptBytes(String cryptedContent, String def_pass, String salt) {
        byte[] content = null;
        try {
            SecretKey key = this.getSecretKey(def_pass, salt);
            content = this.decryptBytes(key, cryptedContent);
        } catch (BaseCrypto.CryptoException e) {
            // Log.e("decryptContent", "decryptContent CryptoException: "+ e.getMessage());
            LOGGER.log(Level.SEVERE, "decryptContent CryptoException: ", e.getMessage() );
        }
        return content;
    }

     public String encryptBytes(byte[] content, String def_pass, String salt) {
        String encryptedContent = "";
        try {
            SecretKey key = this.getSecretKey(def_pass, salt);
            encryptedContent = this.encrypt(key, content);

        } catch (BaseCrypto.CryptoException e) {
            LOGGER.log(Level.SEVERE, "encryptContent CryptoException: ", e.getMessage() );
        }
        return encryptedContent;
    }
    */
