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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import ru.bullyboo.encoder.Base64;
import ru.bullyboo.encoder.constants.Constants;

/**
 * RSA Encrypt/Decrypt class
 */
public class RSA{

    public static final int RSA_MINIMUM_BITS = 512;
    public static final int RSA_MAXIMUM_BITS = 65536;

    /**
     * All RSA methods
     */
    public enum Method{

        RSA ("RSA"),

        RSA_ECB_NO_PADDING ("RSA/ECB/NoPadding"),
        RSA_ECB_PKCS1PADDING ("RSA/ECB/PKCS1Padding"),
        RSA_ECB_OAEPPadding ("RSA/ECB/OAEPPadding"),
        RSA_ECB_PKCS1Padding ("RSA/ECB/PKCS1Padding"),
        RSA_None_NoPadding ("RSA/None/NoPadding"),

        RSA_ECB_OAEP_with_MD5_and_MGF1_PADDING("RSA/ECB/OAEPWithMD5AndMGF1Padding"),
        RSA_ECB_OAEP_with_SHA1_and_MGF1_PADDING("RSA/ECB/OAEPWithSHA1AndMGF1Padding"),
        RSA_ECB_OAEP_with_SHA_1_and_MGF1_PADDING("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
        RSA_ECB_OAEP_with_SHA_224_and_MGF1_PADDING("RSA/ECB/OAEPWithSHA-224AndMGF1Padding"),
        RSA_ECB_OAEP_with_SHA_256_and_MGF1_PADDING("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
        RSA_ECB_OAEP_with_SHA_384_and_MGF1_PADDING("RSA/ECB/OAEPWithSHA-384AndMGF1Padding"),
        RSA_ECB_OAEP_with_SHA_512_and_MGF1_PADDING("RSA/ECB/OAEPWithSHA-512AndMGF1Padding ");

        private final String method;

        Method(String method) {
            this.method = method;
        }

        public String getMethod() {
            return method;
        }
    }


    public static KeySize setKeySize(int keySize){
        return new KeySize(keySize);
    }

    /**
     * This class checks the key size
     * It must range between 512 and 65536 bits.
     * Also keysize must be a multiple of 64
     */
    public static class KeySize{

        private final int size;

        KeySize(int size) {
            if(size >= RSA_MINIMUM_BITS &&
                    size <= RSA_MAXIMUM_BITS){
                if(size % 64 != 0){
                    throw new IllegalStateException(Constants.RSA_KEY_MULTIPLY_EXCEPTION);
                }
                this.size = size;
            } else {
                throw new IllegalStateException(Constants.RSA_KEY_EXCEPTION);
            }
        }
    }

    /**
     * KeyCallback for getting the key
     */
    public interface KeyCallback{

        void onSuccess(KeyPair result);

        void onFailure(Throwable e);
    }

    /**
     * This method generates KeyPair and then sends it to encrypt method
     */
    public static String encrypt(Method method, KeySize keySize, byte[]  message,
                                 KeyCallback keyCallBack) throws Exception {

        return encrypt(method, generateKey(keySize), message, keyCallBack);
    }

    /**
     * This method creates KeyPair object from public and private keys and then, sends it to encrypt method
     */
    public static String encrypt(Method method, PublicKey publicKey, PrivateKey privateKey,
                                 byte[]  message, KeyCallback keyCallBack) throws Exception {

        KeyPair key = new KeyPair(publicKey, privateKey);

        return encrypt(method, key, message, keyCallBack);
    }

    /**
     * Implementation of RSA encryption
     */
    public static String encrypt(Method method, KeyPair key,
                                 byte[]  message, KeyCallback keyCallBack) throws Exception {

        sentKeys(keyCallBack, key);

        Cipher cipher = Cipher.getInstance(method.getMethod());
        cipher.init(Cipher.ENCRYPT_MODE, key.getPublic());
        byte[] cipherText = cipher.doFinal(message);

        return Base64.encodeToString(cipherText, Base64.DEFAULT);
    }

    /**
     * This method gets the private key from KeyPair and sends it to decrypt method
     */
    public static String decrypt(Method method, KeyPair key, byte[]  message) throws Exception {
        return decrypt(method, key.getPrivate(), message);
    }

    /**
     * Implementation of RSA decryption
     */
    public static String decrypt(Method method, PrivateKey privateKey, byte[]  message) throws Exception{

        Cipher cipher = Cipher.getInstance(method.getMethod());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(Base64.decode(message, Base64.DEFAULT));

        return new String(cipherText);
    }

    /**
     * Generation KeyPair with a certain key size
     */
    public static KeyPair generateKey(KeySize keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize.size);

        return kpg.generateKeyPair();
    }

    private static void sentKeys(KeyCallback keyCallBack, KeyPair key) {
        if(keyCallBack != null && key != null){
            keyCallBack.onSuccess(key);
        }
    }
}
