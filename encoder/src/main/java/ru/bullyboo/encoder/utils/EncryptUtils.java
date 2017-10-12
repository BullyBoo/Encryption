package ru.bullyboo.encoder.utils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import ru.bullyboo.encoder.Base64;

/**
 * by BullyBoo on 12.10.2017.
 */

public class EncryptUtils {

    private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

    public static PublicKey getRsaPublicKey(String key){
        if(key == null){
            return null;
        }

        key = key.replace("\n", "")
                .replace(BEGIN_PUBLIC_KEY, "")
                .replace(END_PUBLIC_KEY, "")
                .replaceAll("\\s", "");

        byte[] encodedPublicKey = Base64.decode(key.getBytes(), Base64.DEFAULT);

        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedPublicKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey getRsaPrivateKey(String key){
        if(key == null){
            return null;
        }

        key = key.replace("\n", "")
                .replace(BEGIN_PRIVATE_KEY, "")
                .replace(END_PRIVATE_KEY, "");

        byte[] encodedPublicKey = Base64.decode(key.getBytes(), Base64.DEFAULT);

        try {
            return KeyFactory.getInstance("RSA", "BC").generatePrivate(new PKCS8EncodedKeySpec(encodedPublicKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }
}
