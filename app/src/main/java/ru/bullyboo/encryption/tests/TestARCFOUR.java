package ru.bullyboo.encryption.tests;

import ru.bullyboo.encoder.Encoder;
import ru.bullyboo.encoder.callbacks.EncodeCallback;

/**
 * Created by BullyBoo on 01.04.2017.
 */

public class TestARCFOUR {

    private static final String message = "test text 123\0\0\0"; //Not null padding
    private static final String message1 = "test message"; //with padding
    private static final String key = "test key";
    private static final String vector = "test vector";


    public static void testAll_ARCFOUR(){

        new Thread(new Runnable() {
            @Override
            public void run() {

                for(int i = 1; i <= 8; i++){
                    encrypt_decrypt(i);
                    System.out.println("end check with keySize " + i);
                }
            }
        }).start();
    }

    private static void encrypt_decrypt(int keySize) {

        String encrypt = Encoder.BuilderARCFOUR()
                .message("test message")
                .key("test key")
                .keySize(1024)
                .encrypt();

        String decrypt = Encoder.BuilderARCFOUR()
                .message(encrypt)
                .key(key, keySize)
                .decrypt();


        if(decrypt.equals(message)){
            System.out.println("onSuccess");
            System.out.println("encrypt = " + encrypt);
            System.out.println("decrypt = " + decrypt);
        } else {
            System.out.println("onFailure");
            System.out.println("encrypt = " + encrypt);
            System.out.println("decrypt = " + decrypt);
            System.out.println("keySize = " + keySize);
        }
    }

    public static void testARCFOUR_Async(){

        Encoder.BuilderARCFOUR()
                .message("test message")
                .key("test key")
                .keySize(1024)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encryptAsync();
    }

    private static void testARCFOUR_Async_decrypt(String message){

        Encoder.BuilderARCFOUR()
                .message(message)
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("decryptAsync ARCFOUR onSuccess");
                        System.out.println("decryptAsync ARCFOUR result = " + result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("decryptAsync ARCFOUR onFailure");
                        e.printStackTrace();
                    }
                }).decryptAsync();
    }
}
