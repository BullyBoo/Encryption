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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC Encrypt/Decrypt class
 */
public class HMAC {

    /**
     * All supported methods
     */
    public enum Method{

        HMAC_MD5("HMAC-MD5"),
        HMAC_SHA_1("HMAC-SHA1"),
        HMAC_SHA_224("HMAC-SHA224"),
        HMAC_SHA_256("HMAC-SHA256"),
        HMAC_SHA_384("HMAC-SHA384"),
        HMAC_SHA_512("HMAC-SHA512");


        private final String method;

        Method(String method) {
            this.method = method;
        }

        public String getMethod() {
            return method;
        }

    }

    /**
     * Implementation of HMAC encryption
     */
    public static String encrypt(HMAC.Method method, byte[] key, String message) throws Exception{

        SecretKeySpec keySpec = new SecretKeySpec(key, method.getMethod());

        Mac cipher = Mac.getInstance(method.getMethod());
        cipher.init(keySpec);
        byte[] cipherText = cipher.doFinal(message.getBytes());

        StringBuffer hash = new StringBuffer();
        for (int i = 0; i < cipherText.length; i++) {
            String hex = Integer.toHexString(0xFF & cipherText[i]);
            if (hex.length() == 1) {
                hash.append('0');
            }
            hash.append(hex);
        }

        return hash.toString();
    }

}
