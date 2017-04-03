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

package ru.bullyboo.encoder;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

/**
 * Class for getting hash function from String
 */
public class Hash {

    /**
     * Converting String to md5 hash
     */
    public String md5(String key){
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");

            digest.update(key.getBytes("UTF-8"));

            byte[] messegeDigist = digest.digest();

            StringBuilder hexString = new StringBuilder();

            for (byte b : messegeDigist){
                String h = Integer.toHexString(0xFF & b);

                while (h.length() < 2){
                    h = "0" + h;
                }
                hexString.append(h);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Converting String to md5 hash
     */
    public String sha1(String key){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            byte[] hash = md.digest(key.getBytes("UTF-8"));

            Formatter formatter = new Formatter();

            for (byte b : hash) {
                formatter.format("%02x", b);
            }

            return formatter.toString();

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Converting String to sha224 hash
     */
    public String sha224(String key){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-224");

            byte[] hash = md.digest(key.getBytes("UTF-8"));

            Formatter formatter = new Formatter();

            for (byte b : hash) {
                formatter.format("%02x", b);
            }

            return formatter.toString();

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Converting String to sha256 hash
     */
    public String sha256(String key){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            byte[] hash = md.digest(key.getBytes("UTF-8"));

            Formatter formatter = new Formatter();

            for (byte b : hash) {
                formatter.format("%02x", b);
            }

            return formatter.toString();

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Converting String to sha384 hash
     */
    public String sha384(String key){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-384");

            byte[] hash = md.digest(key.getBytes("UTF-8"));

            Formatter formatter = new Formatter();

            for (byte b : hash) {
                formatter.format("%02x", b);
            }

            return formatter.toString();

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Converting String to sha512 hash
     */
    public String sha512(String key){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");

            byte[] hash = md.digest(key.getBytes("UTF-8"));

            Formatter formatter = new Formatter();

            for (byte b : hash) {
                formatter.format("%02x", b);
            }

            return formatter.toString();

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }
}
