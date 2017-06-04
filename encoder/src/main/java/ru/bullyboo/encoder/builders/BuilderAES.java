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
import ru.bullyboo.encoder.methods.AES;

/**
 * AES Encrypt/Decrypt Builder
 */
public class BuilderAES extends BaseBuilder<BuilderAES>{

    private volatile String method;

    private volatile byte[] key = new byte[]{};
    private volatile AES.Key keySize = AES.Key.SIZE_128;

    private volatile byte[] iVector = new byte[]{};

    /**
     * Set the encryption method for encrypting or decrypting
     */
    public BuilderAES method(AES.Method method) {
        this.method = method.getMethod();
        return this;
    }

    public BuilderAES method(AES.MethodCFB method) {
        this.method = method.getMethod();
        return this;
    }

    public BuilderAES method(AES.MethodOFB method) {
        this.method = method.getMethod();
        return this;
    }

    /**
     * Set the encryption key and its bite size (128, 192, 256)
     */
    public BuilderAES key(String key, AES.Key keySize) {
        this.key = key.getBytes();
        this.keySize = keySize;
        return this;
    }

    public BuilderAES key(String key) {
        this.key = key.getBytes();
        return this;
    }

    public BuilderAES key(byte[] key, AES.Key keySize) {
        this.key = key;
        this.keySize = keySize;
        return this;
    }

    public BuilderAES key(byte[] key) {
        this.key = key;
        return this;
    }

    public BuilderAES keySize(AES.Key keySize){
        this.keySize = keySize;
        return this;
    }

    /**
     * Set initialization vector (IV)
     */
    public BuilderAES iVector(String iVector) {
        this.iVector = iVector.getBytes();
        return this;
    }

    public BuilderAES iVector(byte[] iVector) {
        this.iVector = iVector;
        return this;
    }

    @Override
    String encryption() throws Exception {
        return AES.encrypt(method, key, keySize, iVector, message);
    }

    @Override
    String decryption() throws Exception {
        return AES.decrypt(method, key, keySize, iVector, message);
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
