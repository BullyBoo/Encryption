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
import javax.crypto.spec.SecretKeySpec;

import ru.bullyboo.encoder.Base64;

/**
 * ARCFOUR Encrypt/Decrypt class
 */
public class ARCFOUR extends BaseMethod{

    /**
     * ARCFOUR method
     */
    private static final String ARCFOUR = "ARCFOUR";

    /**
     * Implementation of ARCFOUR encryption
     */
    public static String encrypt(byte[] key, int keySize, String message) throws Exception {

//        generate Key
        byte[] keyBytes = generateKey(key, keySize);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ARCFOUR);

        Cipher cipher = Cipher.getInstance(ARCFOUR);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] cipherText = cipher.doFinal(message.getBytes());

        return Base64.encodeToString(cipherText, Base64.DEFAULT);
    }

    /**
     * Implementation of ARCFOUR decryption
     */
    public static String decrypt(byte[] key, int keySize, String message) throws Exception {

//        generate Key
        byte[] keyBytes = generateKey(key, keySize);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ARCFOUR);

        Cipher cipher = Cipher.getInstance(ARCFOUR);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] cipherText = cipher.doFinal(Base64.decode(message, Base64.DEFAULT));

        return new String(cipherText);
    }
}
