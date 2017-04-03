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
import ru.bullyboo.encoder.methods.Blowfish;

/**
 * Blowfish Encrypt/Decrypt Builder
 */
public class BuilderBlowfish extends BaseBuilder{

    private volatile String message;

    private volatile String method;

    private volatile byte[] key = new byte[]{};
    private volatile int keySize = 1;

    private volatile byte[] iVector = new byte[]{};

    /**
     * Set the message for encrypting or decrypting
     */
    public BuilderBlowfish message(String message) {
        this.message = message;
        return this;
    }

    /**
     * Set the encryption method for encrypting or decrypting
     */
    public BuilderBlowfish method(Blowfish.Method method) {
        this.method = method.getMethod();
        return this;
    }

    public BuilderBlowfish method(Blowfish.MethodCFB method) {
        this.method = method.getMethod();
        return this;
    }

    public BuilderBlowfish method(Blowfish.MethodOFB method) {
        this.method = method.getMethod();
        return this;
    }

    /**
     * Set the encryption key and its bite size
     * Can`t be equals 0
     * Can`t be less then 0
     */
    public BuilderBlowfish key(String key) {
        this.key = key.getBytes();
        return this;
    }

    public BuilderBlowfish key(byte[] key) {
        this.key = key;
        return this;
    }

    public BuilderBlowfish key(String key, int keySize) {
        this.key = key.getBytes();
        this.keySize = keySize;
        return this;
    }

    public BuilderBlowfish key(byte[] key, int keySize) {
        this.key = key;
        this.keySize = keySize;
        return this;
    }

    public BuilderBlowfish keySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    /**
     * Set initialization vector (IV)
     */
    public BuilderBlowfish iVector(String iVector) {
        this.iVector = iVector.getBytes();
        return this;
    }

    public BuilderBlowfish iVector(byte[] iVector) {
        this.iVector = iVector;
        return this;
    }

    @Override
    String encryption() throws Exception {
        return Blowfish.encrypt(method, key, keySize, iVector, message);
    }

    @Override
    String decryption() throws Exception {
        return Blowfish.decrypt(method, key, keySize, iVector, message);
    }

    @Override
    boolean hasEnoughData() {
        if (message == null) {
            throw new NullPointerException(Constants.MESSAGE_EXCEPTION);
        }
        if (method == null) {
            throw new NullPointerException(Constants.METHOD_EXCEPTION);
        }
        if (keySize == 0) {
            throw new IllegalArgumentException(Constants.KEY_SIZE_EXCEPTION);
        } else if (keySize < 0) {
            throw new IllegalArgumentException(Constants.LESS_ZERO_KEY_SIZE_EXCEPTION);
        }
        return true;
    }
}
