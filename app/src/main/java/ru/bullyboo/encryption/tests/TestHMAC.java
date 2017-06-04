package ru.bullyboo.encryption.tests;

import ru.bullyboo.encoder.Encoder;
import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.methods.HMAC;

/**
 * Created by BullyBoo on 28.03.2017.
 */

public class TestHMAC {

    private static final String message = "test text 123\0\0\0"; //Not null padding
    private static final String message1 = "test message"; //with padding
    private static final String key = "test key";
    private static final String vector = "test vector";

    public static void testHMAC(){

        HMAC.Method[] methods = HMAC.Method.values();

        for(HMAC.Method method : methods){

            String encrypt = Encoder.BuilderHMAC()
                    .message("test message")
                    .method(HMAC.Method.HMAC_SHA_1)
                    .key("test key")
                    .encrypt();

            System.out.println("encrypt with " + method.getMethod() + " = " + encrypt);
        }
    }

    public static void testHMAC_Async(){

        Encoder.BuilderHMAC()
                .method(HMAC.Method.HMAC_SHA_1)
                .message("test message")
                .key("test key")
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

    private static void testHMAC_Async_decrypt(String message){

        Encoder.BuilderHMAC()
                .method(HMAC.Method.HMAC_SHA_1)
                .message("")
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("decryptAsync HMAC onSuccess");
                        System.out.println("decryptAsync HMAC result = " + result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("decryptAsync onFailure");
                        e.printStackTrace();
                    }
                }).decryptAsync();
    }
}
