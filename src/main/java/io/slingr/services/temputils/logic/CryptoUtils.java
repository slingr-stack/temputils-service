package io.slingr.services.temputils.logic;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * User: fmilone
 * Date: 9/23/13
 */
public class CryptoUtils {

    private static final Logger logger = LoggerFactory.getLogger(CryptoUtils.class);

    private static String storedKey = "***DO_NOT_MODIFY_THIS***_·$%&!!3342yukh7384b6,3kd!!";
    private static String filesKey = "***DO_NOT_MODIFY_THIS***_·%%&!!5462ywyh8384b6,3bd%!";
    private SecretKey secretKey;
    private Cipher ecipher;
    private Cipher dcipher;

    private static CryptoUtils instance;

    private static final char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private CryptoUtils() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        byte[] encodedKey = Base64.decodeBase64(storedKey);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(storedKey.toCharArray(), encodedKey, 65536, 128);
        SecretKey tmp = factory.generateSecret(spec);
        this.secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        this.ecipher = Cipher.getInstance("AES");
        this.dcipher = Cipher.getInstance("AES");
        this.ecipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
        this.dcipher.init(Cipher.DECRYPT_MODE, this.secretKey);
    }

    public synchronized static CryptoUtils getInstance() {
        if (instance == null) {
            try {
                instance = new CryptoUtils();
            } catch (Exception e) {
                logger.error("Could not initialize crypto utils", e);
            }
        }
        return instance;
    }

    public String encrypt(String plaintext) {
        try {
            return Base64Utils.encode(ecipher.doFinal(plaintext.getBytes("UTF8")));
        } catch (Exception e) {
            return plaintext;
        }
    }

    public String decrypt(String ciphertext) {
        try {
            return new String(dcipher.doFinal(Base64Utils.decodeData(ciphertext)), "UTF8");
        } catch (Exception e) {
            return ciphertext;
        }
    }

    /**
     * Encodes a string using SHA-256. This is a one-way encoding algorithm.
     *
     * @param input the string to encode
     * @param salt  the SALT to be used to encode
     * @return the encoded string
     */
    public String encodeWithSalt(String input, String salt) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Can't find SHA-256 encoding library", e);
        }
        String saltedPassword = input + salt;
        md.update(saltedPassword.getBytes());
        byte[] mdbytes = md.digest();
        // convert to hex
        StringBuilder hexString = new StringBuilder();
        for (byte mdbyte : mdbytes) {
            hexString.append(Integer.toHexString(0xFF & mdbyte));
        }
        return hexString.toString();
    }

    public enum SlingrAlgorithm {
        SHA_1,
        SHA_3,
        SHA_256,
        KECCAK,
        MD5
    }

    public String encode(String input, SlingrAlgorithm algorithm) throws NoSuchAlgorithmException {
        return encode(input, algorithm, 256);
    }

    public String encode(String input, SlingrAlgorithm algorithm, int i) throws NoSuchAlgorithmException {
        Digest digest;
        switch (algorithm) {
            case SHA_3:
                digest = new SHA3Digest(i);
                break;
            case KECCAK:
                digest = new KeccakDigest(i);
                break;
            case SHA_256:
                MessageDigest msgDigest =  MessageDigest.getInstance("SHA-256");
                byte[] encodedhash = msgDigest.digest(
                        input.getBytes(StandardCharsets.UTF_8));
                return toHexString(encodedhash);
            case MD5:
                byte[] bytesOfMessage = input.getBytes();
                MessageDigest md = MessageDigest.getInstance("MD5");
                return new BigInteger(1, md.digest(bytesOfMessage)).toString(16);
            default:
                digest = new SHA1Digest();
                break;
        }
        return hash(input, digest);
    }

    public Boolean verifySignatureWithHmac(String payload, String signature, String secret, String ALGORITHM) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes("UTF-8"), ALGORITHM);
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(signingKey);
        byte[] rawHmac = mac.doFinal(payload.getBytes());
        String hash = new String(toHexString(rawHmac));
        return hash.equals(signature);
    }
    /**
     * Convert a byte array to the corresponding hexstring.
     *
     * @param input the byte array to be converted
     * @return the corresponding hexstring
     */
    public static String toHexString(byte[] input) {
        String result = "";
        for (int i = 0; i < input.length; i++) {
            result += HEX_CHARS[(input[i] >>> 4) & 0x0f];
            result += HEX_CHARS[(input[i]) & 0x0f];
        }
        return result;
    }

    private String hash(String input, Digest digest) {
        digest.update(input.getBytes(StandardCharsets.UTF_8), 0, input.length());
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return toHexString(result);
    }

    public String hs256(String message, String secret) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(signingKey);
        byte[] rawHmac = mac.doFinal(message.getBytes());
        return toHexString(rawHmac);
    }

    public void encryptFile(InputStream is, OutputStream os) throws Exception {
        encryptOrDecrypt(filesKey, Cipher.ENCRYPT_MODE, is, os);
    }

    public void decryptFile(InputStream is, OutputStream os) throws Exception {
        encryptOrDecrypt(filesKey, Cipher.DECRYPT_MODE, is, os);
    }

    private static void encryptOrDecrypt(String key, int mode, InputStream is, OutputStream os) throws Exception {
        DESKeySpec dks = new DESKeySpec(key.getBytes());
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey desKey = skf.generateSecret(dks);
        Cipher cipher = Cipher.getInstance("DES");
        if (mode == Cipher.ENCRYPT_MODE) {
            cipher.init(Cipher.ENCRYPT_MODE, desKey);
            CipherInputStream cis = new CipherInputStream(is, cipher);
            doCopy(cis, os);
        } else if (mode == Cipher.DECRYPT_MODE) {
            cipher.init(Cipher.DECRYPT_MODE, desKey);
            CipherOutputStream cos = new CipherOutputStream(os, cipher);
            doCopy(is, cos);
        }
    }

    private static void doCopy(InputStream is, OutputStream os) throws IOException {
        try {
            IOUtils.copy(is, os);
        } finally {
            os.flush();
            IOUtils.closeQuietly(os);
            IOUtils.closeQuietly(is);
        }
    }

}