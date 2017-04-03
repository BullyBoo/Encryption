package ru.bullyboo.encryption.tests;

import ru.bullyboo.encoder.Encoder;
import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.methods.AES;
import ru.bullyboo.encoder.methods.PBE;

/**
 * Created by BullyBoo on 26.03.2017.
 */

public class TestPBE {

    private static String message = "test message";
    private static String key = "test key";
    private static String vector = "test vector";


    public static void testAll_PBE(){
        PBE.Method[] methods = PBE.Method.values();

        for(PBE.Method method : methods){

            String encrypt = Encoder.BuilderPBE()
                    .message(message)
                    .method(method)
                    .key(key)
                    .iVector(vector)
                    .encrypt();

            System.out.println("encrypt with " + method.getMethod() + " = " + encrypt);

            String decrypt = Encoder.BuilderPBE()
                    .message(encrypt)
                    .method(method)
                    .key(key)
                    .iVector(vector)
                    .decrypt();

            System.out.println("decrypt with " + method.getMethod() + " = " + decrypt);
        }
    }
    public static void testPBE_Async(){

        Encoder.BuilderPBE()
                .method(PBE.Method.PBE_with_MD5_and_AES_128_CBC_OPENSSL)
                .message(message)
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("encrypeAsync PBE onSuccess");
                        System.out.println("decryptAsync PBE result = " + result);
                        testPBE_Async_decrypt(result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("encrypeAsync PBE onFailure");
                        e.printStackTrace();
                    }
                }).encrypeAsync();
    }

    private static void testPBE_Async_decrypt(String message){

        Encoder.BuilderPBE()
                .method(PBE.Method.PBE_with_MD5_and_AES_128_CBC_OPENSSL)
                .message(message)
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("decryptAsync PBE onSuccess");
                        System.out.println("decryptAsync PBE result = " + result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("decryptAsync PBE onFailure");
                        e.printStackTrace();
                    }
                }).decryptAsync();
    }
}
