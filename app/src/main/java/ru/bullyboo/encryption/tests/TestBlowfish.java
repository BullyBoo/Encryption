package ru.bullyboo.encryption.tests;

import ru.bullyboo.encoder.Encoder;
import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.constants.Padding;
import ru.bullyboo.encoder.methods.Blowfish;

/**
 * Created by BullyBoo on 28.03.2017.
 */

public class TestBlowfish {

    private static final String message = "test text 123\0\0\0"; //Not null padding
    private static final String message1 = "test message"; //with padding
    private static final String key = "test key";
    private static final String vector = "test vector";


    public static void testAll_Blowfish(){

        new Thread(new Runnable() {
            @Override
            public void run() {
                Blowfish.Method[] methods = Blowfish.Method.values();

                for(int i = 100000; i <= 100020; i++){
                    for(Blowfish.Method method : methods){
                        encrypt_decrypt(method, i);
                    }
                    System.out.println("end check with keySize " + i);
                }
            }
        }).start();
    }

    private static void encrypt_decrypt(Blowfish.Method method, int keySize) {

        String encrypt = Encoder.BuilderBlowfish()
                .message("test message")
                .method(Blowfish.Method.BLOWFISH_CBC_ISO10126Padding)
                .key(key) // not necessary
                .keySize(1024) // not necessary
                .iVector("test vector") // not necessary
                .encrypt();

        String decrypt = Encoder.BuilderBlowfish()
                .message(encrypt)
                .method(method)
                .key(key, keySize)
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

    public static void testAll_CFB_Blowfish(){
        testAll_CFB(Padding.NO_PADDING);
        testAll_CFB(Padding.PKCS5PADDING);
        testAll_CFB(Padding.PKCS7PADDING);
        testAll_CFB(Padding.ISO10126PADDING);
    }

    private static void testAll_CFB(Padding padding) {
        Blowfish.Method[] methods = Blowfish.Method.values();

        for(int i = 8; i <= 64; i++){
            try {

                Blowfish.MethodCFB methodCFB = Blowfish.MethodCFB.generateMethod(i, padding);
                String encrypt = Encoder.BuilderBlowfish()
                        .message(message)
                        .method(methodCFB)
                        .key(key)
                        .iVector(vector)
                        .encrypt();

                System.out.println("encrypt with " + methodCFB.getMethod() + " = " + encrypt);

                String decrypt = Encoder.BuilderBlowfish()
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

    public static void testAll_OFB_Blowfish(){
        testAll_OFB(Padding.NO_PADDING);
        testAll_OFB(Padding.PKCS5PADDING);
        testAll_OFB(Padding.PKCS7PADDING);
        testAll_OFB(Padding.ISO10126PADDING);
    }

    private static void testAll_OFB(Padding padding) {
        Blowfish.Method[] methods = Blowfish.Method.values();

        for(int i = 8; i <= 64; i++){
            try {

                Blowfish.MethodOFB methodCFB = Blowfish.MethodOFB.generateMethod(i, padding);

                String encrypt = Encoder.BuilderBlowfish()
                        .message(message)
                        .method(methodCFB)
                        .key(key)
                        .iVector(vector)
                        .encrypt();

                System.out.println("encrypt with " + methodCFB.getMethod() + " = " + encrypt);

                String decrypt = Encoder.BuilderBlowfish()
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

    public static void testBlowfish_Async(){

        Encoder.BuilderBlowfish()
                .method(Blowfish.Method.BLOWFISH_CBC_ISO10126Padding)
                .message("test message")
                .key("test key") // not necessary
                .keySize(1024) // not necessary
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

    private static void testBlowfish_Async_decrypt(String message){

        Encoder.BuilderBlowfish()
                .method(Blowfish.Method.BLOWFISH_CBC_ISO10126Padding)
                .message(message)
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("decryptAsync Blowfish onSuccess");
                        System.out.println("decryptAsync Blowfish result = " + result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("decryptAsync onFailure");
                        e.printStackTrace();
                    }
                }).decryptAsync();
    }
}
