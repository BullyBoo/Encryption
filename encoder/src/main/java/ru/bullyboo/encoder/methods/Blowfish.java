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
 * Blowfish Encrypt/Decrypt class
 */
public class Blowfish extends BaseMethod{

    private static final String BLOWFISH_CFB = "Blowfish/CFB";
    private static final String BLOWFISH_OFB = "Blowfish/OFB";

    private static final int VECTOR_LEGHT = 8;

    /**
     * All supported methods
     */
    public enum Method{
        BLOWFISH_ECB_NoPadding ("Blowfish/ECB/NoPadding"),
        BLOWFISH_ECB_PKCS5Padding ("Blowfish/ECB/PKCS5Padding"),
        BLOWFISH_ECB_PKCS7Padding ("Blowfish/ECB/PKCS7Padding"),
        BLOWFISH_ECB_ISO10126Padding ("Blowfish/ECB/ISO10126Padding"),

        BLOWFISH_CBC_NoPadding ("Blowfish/CBC/NoPadding"),
        BLOWFISH_CBC_PKCS5Padding ("Blowfish/CBC/PKCS5Padding"),
        BLOWFISH_CBC_PKCS7Padding ("Blowfish/CBC/PKCS7Padding"),
        BLOWFISH_CBC_ISO10126Padding ("Blowfish/CBC/ISO10126Padding"),

        BLOWFISH_CTR_NoPadding ("Blowfish/CTR/NoPadding"),
        BLOWFISH_CTR_PKCS5Padding ("Blowfish/CTR/PKCS5Padding"),
        BLOWFISH_CTR_PKCS7Padding ("Blowfish/CTR/PKCS7Padding"),
        BLOWFISH_CTR_ISO10126Padding ("Blowfish/CTR/ISO10126Padding"),

        BLOWFISH_CTS_NoPadding ("Blowfish/CTS/NoPadding"),
        BLOWFISH_CTS_PKCS5Padding ("Blowfish/CTS/PKCS5Padding"),
        BLOWFISH_CTS_PKCS7Padding ("Blowfish/CTS/PKCS7Padding"),
        BLOWFISH_CTS_ISO10126Padding ("Blowfish/CTS/ISO10126Padding"),

        BLOWFISH_CFB_NoPadding ("Blowfish/CFB/NoPadding"),
        BLOWFISH_CFB_PKCS5Padding ("Blowfish/CFB/PKCS5Padding"),
        BLOWFISH_CFB_PKCS7Padding ("Blowfish/CFB/PKCS7Padding"),
        BLOWFISH_CFB_ISO10126Padding ("Blowfish/CFB/ISO10126Padding"),

        BLOWFISH_OFB_NoPadding ("Blowfish/OFB/NoPadding"),
        BLOWFISH_OFB_PKCS5Padding ("Blowfish/OFB/PKCS5Padding"),
        BLOWFISH_OFB_PKCS7Padding ("Blowfish/OFB/PKCS7Padding"),
        BLOWFISH_OFB_ISO10126Padding ("Blowfish/OFB/ISO10126Padding");

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
            if(methodNumber >= 8 && methodNumber <=64){
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
     * Blowfish-CBF encryption methods
     * This class implements setting of encryption method number
     */
    public static class MethodCFB extends MethodMode {

        private MethodCFB(String method) {
            super(method);
        }

        public static Blowfish.MethodCFB generateMethod(int methodNumber, Padding padding){
            if(checkNumber(methodNumber)){
                return new Blowfish.MethodCFB(BLOWFISH_CFB + methodNumber + "/" + padding.getPadding());
            } else {
                return null;
            }
        }
    }

    /**
     * Blowfish-OBF encryption methods
     * This class implements setting of encryption method number
     */
    public static class MethodOFB extends MethodMode {

        private MethodOFB(String method) {
            super(method);
        }

        public static Blowfish.MethodOFB generateMethod(int methodNumber, Padding padding){
            if(checkNumber(methodNumber)){
                return new Blowfish.MethodOFB(BLOWFISH_OFB + methodNumber + "/" + padding.getPadding());
            } else {
                return null;
            }
        }
    }

    /**
     * Implementation of Blowfish encryption
     */
    public static String encrypt(String method, byte[] key, int keySize, byte[] vector, byte[] message) throws Exception {

//        generate Key
        byte[] keyBytes = generateKey(key, keySize);
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

        byte[] cipherText = cipher.doFinal(message);

        return Base64.encodeToString(cipherText, Base64.DEFAULT);
    }

    /**
     * Implementation of Blowfish decryption
     */
    public static String decrypt(String method, byte[] key, int keySize, byte[] vector, byte[] message) throws Exception {

//        generate Key
        byte[] keyBytes = generateKey(key, keySize);
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
