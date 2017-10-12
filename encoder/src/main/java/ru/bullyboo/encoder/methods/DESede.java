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

/**
 * DESede Encrypt/Decrypt class
 */
public class DESede extends BaseMethod{

    private static final int VECTOR_LEGHT = 8;

    /**
     * All supported methods
     */
    public enum Method{
        DESEDE ("DESEDE"),
        DESEDE_CBC_NoPadding ("DESEDE/CBC/NoPadding"),
        DESEDE_CBC_PKCS5Padding ("DESEDE/CBC/PKCS5Padding"),
        DESEDE_CBC_PKCS7Padding ("DESEDE/CBC/PKCS7Padding"),
        DESEDE_CBC_ISO10126Padding ("DESEDE/CBC/ISO10126Padding");

        private final String method;

        Method(String method) {
            this.method = method;
        }

        public String getMethod() {
            return method;
        }
    }

    /**
     * Keysize must be equal to 128 or 192 bits.
     * Default Keysize equals 128 bits.
     */
    public enum Key{
        SIZE_128 (16),
        SIZE_192 (24);

        private final int size;

        Key(int size) {
            this.size = size;
        }
    }

    /**
     * Implementation of DESede encryption
     */
    public static String encrypt(Method method, byte[] key, Key keySize, byte[] vector, byte[] message) throws Exception{

//        generate Key
        byte[] keyBytes = generateKey(key, keySize.size);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, method.getMethod());

//        generate Initialization Vector
        byte[] keyBytesIv = generateVector(vector, VECTOR_LEGHT);
        IvParameterSpec ivSpec = new IvParameterSpec(keyBytesIv);

        Cipher cipher = Cipher.getInstance(method.getMethod());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] cipherText = cipher.doFinal(message);

        return Base64.encodeToString(cipherText, Base64.DEFAULT);
    }

    /**
     * Implementation of DESede decryption
     */
    public static String decrypt(Method method, byte[] key, Key keySize, byte[] vector, byte[] message) throws Exception{

//        generate Key
        byte[] keyBytes = generateKey(key, keySize.size);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, method.getMethod());

//        generate Initialization Vector
        byte[] keyBytesIv = generateVector(vector, VECTOR_LEGHT);
        IvParameterSpec ivSpec = new IvParameterSpec(keyBytesIv);

        Cipher cipher = Cipher.getInstance(method.getMethod());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] cipherText = cipher.doFinal(Base64.decode(message, Base64.DEFAULT));

        return new String(cipherText);
    }
}
