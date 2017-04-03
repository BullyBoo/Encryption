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

import ru.bullyboo.encoder.constants.Constants;
import ru.bullyboo.encoder.methods.DESede;

/**
 * AES Encrypt/Decrypt Builder
 */
public class BuilderDESede extends BaseBuilder{

    private volatile String message;

    private volatile DESede.Method method;

    private volatile byte[] key = new byte[]{};
    private volatile DESede.Key keySize = DESede.Key.SIZE_128;

    private volatile byte[] iVector = new byte[]{};

    /**
     * Set the message for encrypting or decrypting
     */
    public BuilderDESede message(String message) {
        this.message = message;
        return this;
    }

    /**
     * Set the encryption method for encrypting or decrypting
     */
    public BuilderDESede method(DESede.Method method) {
        this.method = method;
        return this;
    }

    /**
     * Set the encryption key and its bite size (128, 192)
     */
    public BuilderDESede key(String key, DESede.Key keySize) {
        this.key = key.getBytes();
        this.keySize = keySize;
        return this;
    }

    public BuilderDESede key(String key) {
        this.key = key.getBytes();
        return this;
    }

    public BuilderDESede key(byte[] key, DESede.Key keySize) {
        this.key = key;
        this.keySize = keySize;
        return this;
    }

    public BuilderDESede key(byte[] key) {
        this.key = key;
        return this;
    }

    public BuilderDESede keySize(DESede.Key keySize){
        this.keySize = keySize;
        return this;
    }

    /**
     * Set initialization vector (IV)
     */
    public BuilderDESede iVector(String iVector) {
        this.iVector = iVector.getBytes();
        return this;
    }

    public BuilderDESede iVector(byte[] iVector) {
        this.iVector = iVector;
        return this;
    }


    @Override
    String encryption() throws Exception {
        return DESede.encrypt(method, key, keySize, iVector, message);
    }

    @Override
    String decryption() throws Exception {
        return DESede.decrypt(method, key, keySize, iVector, message);
    }

    @Override
    boolean hasEnoughData() {
        if(message == null){
            throw new NullPointerException(Constants.MESSAGE_EXCEPTION);
        }
        if(method == null){
            throw new NullPointerException(Constants.METHOD_EXCEPTION);
        }
        return true;
    }
}
