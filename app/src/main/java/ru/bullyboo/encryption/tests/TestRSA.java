package ru.bullyboo.encryption.tests;

import java.security.KeyPair;
import java.security.PrivateKey;

import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.Encoder;
import ru.bullyboo.encoder.methods.RSA;

/**
 * Created by BullyBoo on 28.03.2017.
 */

public class TestRSA {

    private static final String message = "test text 123\0\0\0"; //Not null padding
    private static final String message1 = "test message"; //with padding
    private static final String key = "test key";
    private static final String vector = "test vector";

    public static void testAllRSA_Methods(int keySize){
        RSA.Method[] methods = RSA.Method.values();

        for(RSA.Method method : methods){

            try {
                final PrivateKey[] privKey = new PrivateKey[1];
                String encrypt = Encoder.BuilderRSA()
                        .message(message)
                        .method(method)
                        .keySize(RSA.setKeySize(keySize))
                        .keyCallBack(new RSA.KeyCallback() {
                            @Override
                            public void onSuccess(KeyPair key) {
                                privKey[0] = key.getPrivate();
                            }

                            @Override
                            public void onFailure(Throwable e) {
                                System.out.println("encrypt key error");
                            }
                        })
                        .encrypt();

                System.out.println("encrypt with " + method.getMethod() + " and key " + keySize + " = " + encrypt);

                String decrypt = Encoder.BuilderRSA()
                        .message(encrypt)
                        .method(method)
                        .privateKey(null)
                        .decrypt();

                decrypt = decrypt.trim();

                System.out.println("decrypt with " + method.getMethod() + " and key " + keySize + " = " + decrypt);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void testRSA_Method(int keySize){
        RSA.Method[] methods = RSA.Method.values();

        for(RSA.Method method : methods){

            try {
                final PrivateKey[] privKey = new PrivateKey[1];
                String encrypt = Encoder.BuilderRSA()
                        .message(message)
                        .method(method)
                        .keySize(RSA.setKeySize(keySize))
                        .keyCallBack(new RSA.KeyCallback() {
                            @Override
                            public void onSuccess(KeyPair key) {
                                privKey[0] = key.getPrivate();

                            }

                            @Override
                            public void onFailure(Throwable e) {
                                System.out.println("encrypt key error");
                            }
                        })
                        .encrypt();

                System.out.println("encrypt with " + method.getMethod() + " and key " + keySize + " = " + encrypt);

                String decrypt = Encoder.BuilderRSA()
                        .message(encrypt)
                        .method(method)
                        .privateKey(privKey[0])
                        .decrypt();

                decrypt = decrypt.trim();

                System.out.println("decrypt with " + method.getMethod() + " and key " + keySize + " = " + decrypt);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void generateKey(){
        KeyPair key = Encoder.BuilderRSA().keySize(RSA.setKeySize(2048)).generateKey();
        System.out.println("generateKey = " + key);
        System.out.println("generateKey public key = " + key.getPublic());
        System.out.println("generateKey private key = " + key.getPrivate());
    }

    public static void testRSA_Method_WithKey(KeyPair key){
        RSA.Method[] methods = RSA.Method.values();

        for(RSA.Method method : methods){

            try {
                final PrivateKey[] privKey = new PrivateKey[1];
                String encrypt = Encoder.BuilderRSA()
                        .message(message)
                        .method(method)
                        .key(key)
                        .encrypt();

                System.out.println("encrypt with " + method.getMethod() + " = " + encrypt);

                String decrypt = Encoder.BuilderRSA()
                        .message(encrypt)
                        .method(method)
                        .key(key)
                        .decrypt();

                decrypt = decrypt.trim();

                System.out.println("decrypt with " + method.getMethod() + " = " + decrypt);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    static KeyPair keyPair;

    public static void testRSA_Async(){

        Encoder.BuilderRSA()
                .message("test message")
                .method(RSA.Method.RSA_ECB_OAEP_with_MD5_and_MGF1_PADDING)
                .keySize(RSA.setKeySize(4096))
                .keyCallBack(new RSA.KeyCallback() {
                    @Override
                    public void onSuccess(KeyPair key) {
                        System.out.println("encrypt RSA key taken");
                        keyPair = key;
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("encrypt RSA key error");
                        e.printStackTrace();
                    }
                })
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("encrypeAsync RSA with " + RSA.Method.RSA_ECB_OAEP_with_MD5_and_MGF1_PADDING +
                                " = " + result);
                        testRSA_Async_decrypt(keyPair, result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("encrypeAsync RSA error");
                        e.printStackTrace();
                    }
                })
                .encrypeAsync();
    }

    private static void testRSA_Async_decrypt(KeyPair key, String message){

        Encoder.BuilderRSA()
                .message(message)
                .method(RSA.Method.RSA_ECB_OAEP_with_MD5_and_MGF1_PADDING)
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("decryptAsync RSA with " + RSA.Method.RSA_ECB_OAEP_with_MD5_and_MGF1_PADDING + " = " + result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("decryptAsync RSA error");
                        e.printStackTrace();
                    }
                })
                .decryptAsync();
    }

    public static void testRSA_Async_generateKey(){

        Encoder.BuilderRSA()
                .message(message)
                .method(RSA.Method.RSA_ECB_OAEP_with_MD5_and_MGF1_PADDING)
                .keySize(RSA.setKeySize(4096))
                .keyCallBack(new RSA.KeyCallback() {
                    @Override
                    public void onSuccess(KeyPair result) {
                        System.out.println("generateKeyAsync RSA onSuccess");
                        System.out.println("generateKeyAsync RSA public key = " + result.getPublic());
                        System.out.println("generateKeyAsync RSA private key = " + result.getPrivate());
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("generateKeyAsync RSA onFailure");
                        e.printStackTrace();
                    }
                })
                .generateKeyAsync();
    }
}
