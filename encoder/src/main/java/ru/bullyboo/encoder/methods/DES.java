/*
 * Copyright (C) 2017 BullyBoo
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ru.bullyboo.encoder.methods;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ru.bullyboo.encoder.Base64;
import ru.bullyboo.encoder.constants.Constants;
import ru.bullyboo.encoder.constants.Padding;

/**
 * DES Encrypt/Decrypt class
 */
public class DES extends BaseMethod{

    private static final String DES_CFB = "DES/CFB";
    private static final String DES_OFB = "DES/OFB";

    private static final int KEY_LEGHT = 8;
    private static final int VECTOR_LEGHT = 8;

    /**
     * All supported methods
     */
    public enum Method{
        DES_ECB_NoPadding ("DES/ECB/NoPadding"),
        DES_ECB_PKCS5Padding ("DES/ECB/PKCS5Padding"),
        DES_ECB_PKCS7Padding ("DES/ECB/PKCS7Padding"),
        DES_ECB_ISO10126Padding ("DES/ECB/ISO10126Padding"),

        DES_CBC_NoPadding ("DES/CBC/NoPadding"),
        DES_CBC_PKCS5Padding ("DES/CBC/PKCS5Padding"),
        DES_CBC_PKCS7Padding ("DES/CBC/PKCS7Padding"),
        DES_CBC_ISO10126Padding ("DES/CBC/ISO10126Padding"),

        DES_CTR_NoPadding ("DES/CTR/NoPadding"),
        DES_CTR_PKCS5Padding ("DES/CTR/PKCS5Padding"),
        DES_CTR_PKCS7Padding ("DES/CTR/PKCS7Padding"),
        DES_CTR_ISO10126Padding ("DES/CTR/ISO10126Padding"),

        DES_CTS_NoPadding ("DES/CTS/NoPadding"),
        DES_CTS_PKCS5Padding ("DES/CTS/PKCS5Padding"),
        DES_CTS_PKCS7Padding ("DES/CTS/PKCS7Padding"),
        DES_CTS_ISO10126Padding ("DES/CTS/ISO10126Padding"),

        DES_CFB_NoPadding ("DES/CFB/NoPadding"),
        DES_CFB_PKCS5Padding ("DES/CFB/PKCS5Padding"),
        DES_CFB_PKCS7Padding ("DES/CFB/PKCS7Padding"),
        DES_CFB_ISO10126Padding ("DES/CFB/ISO10126Padding"),

        DES_OFB_NoPadding ("DES/OFB/NoPadding"),
        DES_OFB_PKCS5Padding ("DES/OFB/PKCS5Padding"),
        DES_OFB_PKCS7Padding ("DES/OFB/PKCS7Padding"),
        DES_OFB_ISO10126Padding ("DES/OFB/ISO10126Padding");

        private final String method;

        Method(String method) {
            this.method = method;
        }

        public String getMethod() {
            return method;
        }
    }

    static abstract class MethodMode{

        private MethodMode(String method){
            this.method = method;
        }

        static String method;

        static boolean checkNumber(int methodNumber){
            if(methodNumber >= 8 && methodNumber <= 64){
                return true;
            } else {
                throw new IllegalStateException(Constants.METHOD_CFB_OFB_EXCEPTION);
            }
        }

        public String getMethod() {
            return method;
        }
    }

    /**
     * DES-CBF encryption methods
     * This class implements setting of encryption method number
     */
    public static class MethodCFB extends MethodMode {

        private MethodCFB(String method) {
            super(method);
        }

        public static MethodCFB generateMethod(int methodNumber, Padding padding){
            if(checkNumber(methodNumber)){
                return new MethodCFB(DES_CFB + methodNumber + "/" + padding.getPadding());
            } else {
                return null;
            }
        }
    }

    /**
     * DES-OBF encryption methods
     * This class implements setting of encryption method number
     */
    public static class MethodOFB extends MethodMode {

        private MethodOFB(String method) {
            super(method);
        }

        public static MethodOFB generateMethod(int methodNumber, Padding padding){
            if(checkNumber(methodNumber)){
                return new MethodOFB(DES_OFB + methodNumber + "/" + padding.getPadding());
            } else {
                return null;
            }
        }
    }

    /**
     * Implementation of DES encryption
     */
    public static String encrypt(String method, byte[] key, byte[] vector, String message) throws Exception {

//        generate Key
        byte[] keyBytes = generateKey(key, KEY_LEGHT);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, method);

//        generate Initialization Vector
        byte[] keyBytesIv = generateVector(vector, VECTOR_LEGHT);
        IvParameterSpec ivSpec = new IvParameterSpec(keyBytesIv);

        Cipher cipher = Cipher.getInstance(method);

        if(hasInitVector(method)){
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        }

        byte[] cipherText = cipher.doFinal(message.getBytes());

        return Base64.encodeToString(cipherText, Base64.DEFAULT);
    }

    /**
     * Implementation of DES decryption
     */
    public static String decrypt(String method, byte[] key, byte[] vector, String message) throws Exception{

//        generate Key
        byte[] keyBytes = generateKey(key, KEY_LEGHT);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, AES.Method.AES.getMethod());

//        generate Initialization Vector
        byte[] keyBytesIv = generateVector(vector, VECTOR_LEGHT);
        IvParameterSpec ivSpec = new IvParameterSpec(keyBytesIv);

        Cipher cipher = Cipher.getInstance(method);

        if(hasInitVector(method)){
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        }

        byte[] cipherText = cipher.doFinal(Base64.decode(message, Base64.DEFAULT));

        return new String(cipherText);
    }
}
