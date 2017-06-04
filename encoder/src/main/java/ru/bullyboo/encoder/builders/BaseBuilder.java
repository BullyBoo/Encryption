/*
 * Copyright (C) 2017 BullyBoo
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ru.bullyboo.encoder.builders;

import java.nio.ByteBuffer;

import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.threads.BaseThread;
import ru.bullyboo.encoder.threads.EncodingThread;

/**
 * This class implements basic function of synchronous and asynchronous encoding
 */
public abstract class BaseBuilder<B extends BaseBuilder>{

    byte[] message;

    /**
     * Callback for getting the result of encryption
     */
    volatile EncodeCallback callback;

    /**
     * Set the message for encrypting or decrypting
     */
    public B message(byte[] message) {
        this.message = message;

        return (B) this;
    }

    public B message(short message) {
        this.message = ByteBuffer.allocate(4).putShort(message).array();
        return (B) this;
    }

    public B message(short ... message) {
        int size = message.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 * size);

        for(short i : message){
            buffer.putShort(i);
        }
        this.message = buffer.array();
        return (B) this;
    }

    public B message(int message) {
        this.message = ByteBuffer.allocate(4).putInt(message).array();

        return (B) this;
    }

    public B message(int... message) {
        int size = message.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 * size);

        for(int i : message){
            buffer.putInt(i);
        }
        this.message = buffer.array();
        return (B) this;
    }

    public B message(float message) {
        this.message = ByteBuffer.allocate(4).putFloat(message).array();

        return (B) this;
    }

    public B message(float... message) {
        int size = message.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 * size);

        for(float i : message){
            buffer.putFloat(i);
        }
        this.message = buffer.array();
        return (B) this;
    }

    public B message(long message) {
        this.message = ByteBuffer.allocate(4).putLong(message).array();

        return (B) this;
    }

    public B message(long... message) {
        int size = message.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 * size);

        for(long i : message){
            buffer.putLong(i);
        }
        this.message = buffer.array();
        return (B) this;
    }

    public B message(double message) {
        this.message = ByteBuffer.allocate(4).putDouble(message).array();

        return (B) this;
    }

    public B message(double... message) {
        int size = message.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 * size);

        for(double i : message){
            buffer.putDouble(i);
        }
        this.message = buffer.array();
        return (B) this;
    }

    public B message(String message) {
        this.message = message.getBytes();

        return (B) this;
    }

    /**
     * Set the callback
     */
    public BaseBuilder encryptCallBack(EncodeCallback callback){
        this.callback = callback;
        return this;
    }

    /**
     * Start of asynchronous encrypting
    */
    public void encryptAsync(){
        if(hasEnoughData()){
            BaseThread.EncodeAction action = new BaseThread.EncodeAction() {
                @Override
                public String action() {
                    try {
                        return encryption();
                    } catch (Exception e) {
                        callback.onFailure(e);
                    }
                    return null;
                }
            };

            new EncodingThread(action, new BaseThread.ThreadCallback<String>() {
                @Override
                public void onFinish(String parametr) {
                    callback.onSuccess(parametr);
                }

                @Override
                public void onFailed(Throwable e) {
                    callback.onFailure(e);
                }
            }).start();
        }
    }

    /**
     * Start of asynchronous decrypting
     */
    public void decryptAsync(){
        if(hasEnoughData()){
            BaseThread.EncodeAction action = new BaseThread.EncodeAction() {
                @Override
                public String action() {
                    try {
                        return decryption();
                    } catch (Exception e) {
                        callback.onFailure(e);
                    }
                    return null;
                }
            };

            new EncodingThread(action, new BaseThread.ThreadCallback<String>() {
                @Override
                public void onFinish(String parametr) {
                    callback.onSuccess(parametr);
                }

                @Override
                public void onFailed(Throwable e) {
                    callback.onFailure(e);
                }
            }).start();
        }
    }

    /**
     * Start of synchronous encrypting
     */
    public String encrypt(){
        try {
            if(hasEnoughData()){
                return encryption();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Start of synchronous decrypting
     */
    public String decrypt(){
        try {
            if(hasEnoughData()){
                return decryption();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Implementation of calling encryption and decryption
     */
    abstract String encryption() throws Exception ;

    abstract String decryption() throws Exception ;

    /**
     * Method for checking all set data in Builder
     */
    abstract boolean hasEnoughData();

}
