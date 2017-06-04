package ru.bullyboo.encryption.tests;

import ru.bullyboo.encoder.Encoder;
import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.constants.Padding;
import ru.bullyboo.encoder.methods.DES;

/**
 * Created by BullyBoo on 28.03.2017.
 */

public class TestDES {

    private static final String message = "test text 123\0\0\0"; //Not null padding
    private static final String message1 = "test message"; //with padding
    private static final String key = "test key";
    private static final String vector = "test vector";


    public static void testAll_DES(){

        new Thread(new Runnable() {
            @Override
            public void run() {
                DES.Method[] methods = DES.Method.values();

                for(DES.Method method : methods){
                    encrypt_decrypt(method, 8);
                }
                System.out.println("end check with keySize " + 8);
            }
        }).start();
    }

    private static void encrypt_decrypt(DES.Method method, int keySize) {

        String encrypt = Encoder.BuilderDES()
                .message("test message")
                .method(DES.Method.DES_CBC_ISO10126Padding)
                .key("test key") // not necessary
                .iVector("test vector") // not necessary
                .encrypt();

        String decrypt = Encoder.BuilderDES()
                .message(encrypt)
                .method(method)
                .key(key)
                .iVector(vector)
                .decrypt();

        if(decrypt.equals(message)){
//            System.out.println("onSuccess");
        } else {
            System.out.println("onFailure");
            System.out.println("encrypt = " + encrypt);
            System.out.println("decrypt = " + decrypt);
            System.out.println("method = " + method.getMethod());
            System.out.println("keySize = " + keySize);
        }
    }

    public static void testAll_CFB_DES(){
        testAll_CFB(Padding.NO_PADDING);
        testAll_CFB(Padding.PKCS5PADDING);
        testAll_CFB(Padding.PKCS7PADDING);
        testAll_CFB(Padding.ISO10126PADDING);
    }

    private static void testAll_CFB(Padding padding) {
        DES.Method[] methods = DES.Method.values();

        for(int i = 8; i <= 64; i++){
            try {

                DES.MethodCFB methodCFB = DES.MethodCFB.generateMethod(i, padding);
                String encrypt = Encoder.BuilderDES()
                        .message(message)
                        .method(methodCFB)
                        .key(key)
                        .iVector(vector)
                        .encrypt();

                System.out.println("encrypt with " + methodCFB.getMethod() + " = " + encrypt);

                String decrypt = Encoder.BuilderDES()
                        .message(encrypt)
                        .method(methodCFB)
                        .key(key)
                        .iVector(vector)
                        .decrypt();

                System.out.println("decrypt with " + methodCFB.getMethod() + " = " + decrypt);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void testAll_OFB_DES(){
        testAll_OFB(Padding.NO_PADDING);
        testAll_OFB(Padding.PKCS5PADDING);
        testAll_OFB(Padding.PKCS7PADDING);
        testAll_OFB(Padding.ISO10126PADDING);
    }

    private static void testAll_OFB(Padding padding) {
        DES.Method[] methods = DES.Method.values();

        for(int i = 8; i <= 64; i++){
            try {

                DES.MethodOFB methodCFB = DES.MethodOFB.generateMethod(i, padding);
                String encrypt = Encoder.BuilderDES()
                        .message(message)
                        .method(methodCFB)
                        .key(key)
                        .iVector(vector)
                        .encrypt();

                System.out.println("encrypt with " + methodCFB.getMethod() + " = " + encrypt);

                String decrypt = Encoder.BuilderDES()
                        .message(encrypt)
                        .method(methodCFB)
                        .key(key)
                        .iVector(vector)
                        .decrypt();

                System.out.println("decrypt with " + methodCFB.getMethod() + " = " + decrypt);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void testDES_Async(){

        Encoder.BuilderDES()
                .method(DES.Method.DES_CBC_ISO10126Padding)
                .message("test message")
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("encryptAsync DES onSuccess");
                        System.out.println("decryptAsync DES result = " + result);
                        testDES_Async_decrypt(result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("encryptAsync DES onFailure");
                        e.printStackTrace();
                    }
                }).encryptAsync();
    }

    private static void testDES_Async_decrypt(String message){

        Encoder.BuilderDES()
                .method(DES.Method.DES_CBC_ISO10126Padding)
                .message("test message")
                .key("test key") // not necessary
                .iVector("test vector") // not necessary
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
}
