package io.slingr.services.temputils.logic;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

/**
 * Helper that permits to work with Base64 streams
 *
 * <p>Created by smoyano on 02/09/18.
 */
public class Base64Utils {
    /**
     * Encodes binary data using the base64 algorithm but does not chunk the output.
     *
     * @param string data to encode
     * @return string containing Base64 characters in their UTF-8 representation.
     */
    public static String encode(String string){
        return encode(StringUtils.isBlank(string) ? "".getBytes() : string.getBytes());
    }

    /**
     * Encodes binary data using the base64 algorithm but does not chunk the output.
     *
     * @param bytes binary data to encode
     * @return string containing Base64 characters in their UTF-8 representation.
     */
    public static String encode(byte[] bytes){
        return new String(Base64.encodeBase64(bytes));
    }

    /**
     * Decodes Base64 data into octets
     *
     * @param base64Data Byte array containing Base64 data
     * @return Array containing decoded data.
     */
    public static String decode(byte[] base64Data){
        return new String(decodeData(base64Data));
    }

    /**
     * Decodes a Base64 String into octets
     *
     * @param base64String String containing Base64 data
     * @return Array containing decoded data.
     */
    public static String decode(String base64String){
        return new String(decodeData(base64String));
    }

    /**
     * Decodes Base64 data into octets
     *
     * @param base64Data Byte array containing Base64 data
     * @return Array containing decoded data.
     */
    public static byte[] decodeData(byte[] base64Data){
        return Base64.decodeBase64(base64Data);
    }

    /**
     * Decodes a Base64 String into octets
     *
     * @param base64String String containing Base64 data
     * @return Array containing decoded data.
     */
    public static byte[] decodeData(String base64String){
        return Base64.decodeBase64(base64String);
    }


}
