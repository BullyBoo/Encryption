package ru.bullyboo.encryption.tests;

import ru.bullyboo.encoder.Encoder;
import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.constants.Padding;
import ru.bullyboo.encoder.methods.AES;

/**
 * Created by BullyBoo on 28.03.2017.
 */

public class TestAES {

    private static final String message = "test text 123\0\0\0"; //Not null padding
    private static final String message1 = "test message"; //with padding
    private static final String key = "test key";
    private static final String vector = "test vector";

    public static void testAllAES_Methods(){

        testAES_Methods(AES.Key.SIZE_128);
        testAES_Methods(AES.Key.SIZE_192);
        testAES_Methods(AES.Key.SIZE_256);
    }

    private static void testAES_Methods(AES.Key keySize) {

        AES.Method[] methods = AES.Method.values();

        for(AES.Method method : methods){
            String encrypt = Encoder.BuilderAES()
                    .method(AES.Method.AES_CBC_PKCS5PADDING)
                    .message("test message")
                    .key("test key") // not necessary
                    .keySize(AES.Key.SIZE_128) // not necessary
                    .iVector("test vector") // not necessary
                    .encrypt();

//            System.out.println("encrypt with " + method.getMethod() + " and key " + keySize + " = " + encrypt);

            String decrypt = Encoder.BuilderAES()
                    .message(encrypt)
                    .method(method)
                    .key(key, keySize)
                    .iVector(vector)
                    .decrypt();

//            System.out.println("decrypt with " + method.getMethod() + " and key " + keySize + " = " + decrypt);

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
        System.out.println("testAES_Methods onSuccess");
    }

    public static void testCBF_AESMethods(){

        testCBF_Methods(AES.Key.SIZE_128, Padding.NO_PADDING);
        testCBF_Methods(AES.Key.SIZE_128, Padding.PKCS5PADDING);
        testCBF_Methods(AES.Key.SIZE_128, Padding.PKCS7PADDING);
        testCBF_Methods(AES.Key.SIZE_128, Padding.ISO10126PADDING);

        testCBF_Methods(AES.Key.SIZE_192, Padding.NO_PADDING);
        testCBF_Methods(AES.Key.SIZE_192, Padding.PKCS5PADDING);
        testCBF_Methods(AES.Key.SIZE_192, Padding.PKCS7PADDING);
        testCBF_Methods(AES.Key.SIZE_192, Padding.ISO10126PADDING);

        testCBF_Methods(AES.Key.SIZE_256, Padding.NO_PADDING);
        testCBF_Methods(AES.Key.SIZE_256, Padding.PKCS5PADDING);
        testCBF_Methods(AES.Key.SIZE_256, Padding.PKCS7PADDING);
        testCBF_Methods(AES.Key.SIZE_256, Padding.ISO10126PADDING);

        System.out.println("testCBF_Methods onSuccess");
    }

    private static void testCBF_Methods(AES.Key keySize, Padding padding){
        AES.Method[] methods = AES.Method.values();

        for(int i = 8; i <= 128; i++){
            AES.MethodCFB methodCFB = AES.MethodCFB.generateMethod(i, padding);

            String encrypt = Encoder.BuilderAES()
                    .message(message)
                    .method(methodCFB)
                    .key(key, keySize)
                    .iVector(vector)
                    .encrypt();

            String decrypt = Encoder.BuilderAES()
                    .message(encrypt)
                    .method(methodCFB)
                    .key(key, keySize)
                    .iVector(vector)
                    .decrypt();

            if(decrypt.equals(message)){
//            System.out.println("onSuccess");
            } else {
                System.out.println("onFailure");
                System.out.println("encrypt = " + encrypt);
                System.out.println("decrypt = " + decrypt);
                System.out.println("method = " + methodCFB.getMethod());
                System.out.println("keySize = " + keySize);
            }
        }
    }

    public static void testOBF_AESMethods(){

        testOBF_Methods(AES.Key.SIZE_128, Padding.NO_PADDING);
        testOBF_Methods(AES.Key.SIZE_128, Padding.PKCS5PADDING);
        testOBF_Methods(AES.Key.SIZE_128, Padding.PKCS7PADDING);
        testOBF_Methods(AES.Key.SIZE_128, Padding.ISO10126PADDING);

        testOBF_Methods(AES.Key.SIZE_192, Padding.NO_PADDING);
        testOBF_Methods(AES.Key.SIZE_192, Padding.PKCS5PADDING);
        testOBF_Methods(AES.Key.SIZE_192, Padding.PKCS7PADDING);
        testOBF_Methods(AES.Key.SIZE_192, Padding.ISO10126PADDING);

        testOBF_Methods(AES.Key.SIZE_256, Padding.NO_PADDING);
        testOBF_Methods(AES.Key.SIZE_256, Padding.PKCS5PADDING);
        testOBF_Methods(AES.Key.SIZE_256, Padding.PKCS7PADDING);
        testOBF_Methods(AES.Key.SIZE_256, Padding.ISO10126PADDING);

        System.out.println("testOBF_AESMethods onSuccess");
    }

    private static void testOBF_Methods(AES.Key keySize, Padding padding){
        AES.Method[] methods = AES.Method.values();

        for(int i = 8; i <= 128; i++){
            AES.MethodOFB methodCFB = AES.MethodOFB.generateMethod(i, padding);

            String encrypt = Encoder.BuilderAES()
                    .message(message)
                    .method(methodCFB)
                    .key(key, keySize)
                    .iVector(vector)
                    .encrypt();

//            System.out.println("encrypt with " + methodCFB.getMethod() + " and key " + keySize + " = " + encrypt);

            String decrypt = Encoder.BuilderAES()
                    .message(encrypt)
                    .method(methodCFB)
                    .key(key, keySize)
                    .iVector(vector)
                    .decrypt();

//            System.out.println("decrypt with " + methodCFB.getMethod() + " and key " + keySize + " = " + decrypt);

            if(decrypt.equals(message)){
//            System.out.println("onSuccess");
            } else {
                System.out.println("onFailure");
                System.out.println("encrypt = " + encrypt);
                System.out.println("decrypt = " + decrypt);
                System.out.println("method = " + methodCFB.getMethod());
                System.out.println("keySize = " + keySize);
            }
        }
    }

    public static void testAES_Async(){

        Encoder.BuilderAES()
                .method(AES.Method.AES_CBC_PKCS5PADDING)
                .message("test message")
                .key("test key") // not necessary
                .keySize(AES.Key.SIZE_128) // not necessary
                .iVector("test vector") // not necessary
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO somethink
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encryptAsync();

    }

    private static void testAES_Async_decrypt(final String mes){

        Encoder.BuilderAES()
                .method(AES.Method.AES_CBC_PKCS5PADDING)
                .message(mes)
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        if(result.equals(message)){
                            System.out.println("decryptAsync AES onSuccess");
                        } else {
                            System.out.println("decryptAsync AES onFailure");
                        }
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("decryptAsync AES onFailure");
                        e.printStackTrace();
                    }
                }).decryptAsync();
    }
}
