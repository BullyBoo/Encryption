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

package ru.bullyboo.encoder.hashes;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

/**
 * Class for getting hash function from String
 */
public class Hash {

    /**
     * Converting String to md2 hash
     */
    public String md2(String message){
        byte[] hash = new MD2().getHash(message);

        StringBuilder hexString = new StringBuilder();

        for(int i = 0; i < 16; i++){
            String h = Integer.toHexString(0xFF & hash[i]);

            while (h.length() < 2){
                h = "0" + h;
            }
            hexString.append(h);
        }

        return hexString.toString();
    }

    /**
     * Converting String to md4 hash
     */
    public String md4(String message){
        return new MD4().getHash(message);
    }

    /**
     * Converting String to md5 hash
     */
    public String md5(String message){
        return new MD5().getHash(message);
    }

    /**
     * Converting String to md5 hash
     */
    public String sha1(String message){
        return new SHA1().getHash(message);
    }

    /**
     * Converting String to sha224 hash
     */
    public String sha224(String message){
        return new SHA224().getHash(message);
    }

    /**
     * Converting String to sha256 hash
     */
    public String sha256(String message){
        return new SHA256().getHash(message);
    }

    /**
     * Converting String to sha384 hash
     */
    public String sha384(String message){
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-384");

            byte[] hash = digest.digest(message.getBytes());

            Formatter formatter = new Formatter();

            for (byte b : hash) {
                formatter.format("%02x", b);
            }

            return formatter.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Converting String to sha512 hash
     */
    public String sha512(String message){
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");

            byte[] hash = digest.digest(message.getBytes());

            Formatter formatter = new Formatter();

            for (byte b : hash) {
                formatter.format("%02x", b);
            }

            return formatter.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Converting String to adler32 hash
     */
    public String adler32(String message){
        return new Adler32().getHash(message);
    }

    /**
     * Converting String to fnv132 hash
     */
    public String fnv132(String message){
        return new FNV132().getHash(message);
    }

    /**
     * Converting String to ripemd128 hash
     */
    public String ripemd128(String message){
        return new RIPEMD_128().getHash(message);
    }

    /**
     * Converting String to ripemd160 hash
     */
    public String ripemd160(String message){
        return new RIPEMD_160().getHash(message);
    }

    /**
     * Converting String to ripemd256 hash
     */
    public String ripemd256(String message){
        return new RIPEMD_256().getHash(message);
    }

    /**
     * Converting String to ripemd320 hash
     */
    public String ripemd320(String message){
        return new RIPEMD_320().getHash(message);
    }

}
