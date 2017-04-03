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

import java.io.UnsupportedEncodingException;

/**
 * Basic encryption class
 */
abstract class BaseMethod {

    /**
     * Method for creation of valid byte array from key
     */
    static byte[] generateKey(byte[] key, int lenght) throws UnsupportedEncodingException {
        byte[] keyBytes = new byte[lenght];
        int len = key.length;

        if (len > keyBytes.length) {
            len = keyBytes.length;
        }

        System.arraycopy(key, 0, keyBytes, 0, len);
        return keyBytes;
    }

    /**
     * Method for creation of valid byte array from initialization vector
     */
    static byte[] generateVector(byte[] vector, int lenght) throws UnsupportedEncodingException {
        byte[] keyBytesIv = new byte[lenght];
        int len = vector.length;

        if (len > keyBytesIv.length) {
            len = keyBytesIv.length;
        }

        System.arraycopy(vector, 0, keyBytesIv, 0, len);
        return keyBytesIv;
    }

    /**
     * This method contains a list of encryption methods, that do does not have a initialization vector
     */
    public static boolean hasInitVector(String method){

//        All ECB methods do not support initialization vector
        if(method.contains("ECB")){
            return false;
        }

        switch (method){
            case "PBEWITHSHA1AND128BITRC4":
            case "PBEWITHSHA1AND40BITRC4":
            case "PBEWITHSHAAND128BITRC4":
            case "PBEWITHSHAAND40BITRC4":
                return false;
        }
        return true;
    }
}
