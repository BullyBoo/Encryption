package ru.bullyboo.encryption.tests;

import ru.bullyboo.encoder.Encoder;
import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.methods.DES;
import ru.bullyboo.encoder.methods.DESede;

/**
 * Created by BullyBoo on 28.03.2017.
 */

public class TestDESede {

    private static final String message = "test text 123\0\0\0"; //Not null padding
    private static final String message1 = "test message"; //with padding
    private static final String key = "test key";
    private static final String vector = "test vector";

    public static void testAll_DESede(){
        testAll(DESede.Key.SIZE_128);
        testAll(DESede.Key.SIZE_192);
    }

    private static void testAll(DESede.Key keySize) {
        DESede.Method[] methods = DESede.Method.values();

        for(DESede.Method method : methods){
            try {
                String encrypt = Encoder.BuilderDESede()
                        .message(message)
                        .method(method)
                        .key(key, keySize)
                        .iVector(vector)
                        .encrypt();

                System.out.println("encrypt with " + method.getMethod() + " = " + encrypt);

                String decrypt = Encoder.BuilderDESede()
                        .message(encrypt)
                        .method(method)
                        .key(key, keySize)
                        .iVector(vector)
                        .decrypt();

                System.out.println("decrypt with " + method.getMethod() + " = " + decrypt);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void testDESede_Async(){

        Encoder.BuilderDESede()
                .method(DESede.Method.DESEDE_CBC_ISO10126Padding)
                .message(message)
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("encrypeAsync DESede onSuccess");
                        System.out.println("decryptAsync DESede result = " + result);
                        testDESede_Async_decrypt(result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("encrypeAsync DESede onFailure");
                        e.printStackTrace();
                    }
                }).encrypeAsync();
    }

    private static void testDESede_Async_decrypt(String message){

        Encoder.BuilderDESede()
                .method(DESede.Method.DESEDE_CBC_ISO10126Padding)
                .message(message)
                .key(key)
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        System.out.println("decryptAsync DESede onSuccess");
                        System.out.println("decryptAsync DESede result = " + result);
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        System.out.println("decryptAsync onFailure");
                        e.printStackTrace();
                    }
                }).decryptAsync();
    }
}
