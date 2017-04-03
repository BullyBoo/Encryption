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

import ru.bullyboo.encoder.callbacks.EncodeCallback;
import ru.bullyboo.encoder.threads.BaseThread;
import ru.bullyboo.encoder.threads.EncodingThread;

/**
 * This class implements basic function of synchronous and asynchronous encoding
 */
public abstract class BaseBuilder {

    /**
     * Callback for getting the result of encryption
     */
    volatile EncodeCallback callback;

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
    public void encrypeAsync(){
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
