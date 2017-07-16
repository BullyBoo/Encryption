package ru.bullyboo.encryption.tests;

import ru.bullyboo.encoder.Encoder;

/**
 * Created by BullyBoo on 01.04.2017.
 */

public class TestHash {

    private static final String message = "test message"; //with padding

    public static void testHash(){
        System.out.println("md2 = " + Encoder.Hashes().md2(message));
        System.out.println("md4 = " + Encoder.Hashes().md4(message));
        System.out.println("md5 = " + Encoder.Hashes().md5(message));
        System.out.println("sha1 = " + Encoder.Hashes().sha1(message));
        System.out.println("sha224 = " + Encoder.Hashes().sha224(message));
        System.out.println("sha256 = " + Encoder.Hashes().sha256(message));
        System.out.println("sha384 = " + Encoder.Hashes().sha384(message));
        System.out.println("sha512 = " + Encoder.Hashes().sha512(message));
    }
}
