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
import ru.bullyboo.encoder.methods.HMAC;

/**
 * HMAC Encrypt/Decrypt Builder
 */
public class BuilderHMAC extends BaseBuilder{

    private volatile String message;

    private volatile HMAC.Method method;

    private volatile byte[] key;

    /**
     * Set the message for encrypting or decrypting
     */
    public BuilderHMAC message(String message) {
        this.message = message;
        return this;
    }

    /**
     * Set the encryption method for encrypting or decrypting
     */
    public BuilderHMAC method(HMAC.Method method) {
        this.method = method;
        return this;
    }

    /**
     * Set the encryption key
     */
    public BuilderHMAC key(String key) {
        this.key = key.getBytes();
        return this;
    }

    public BuilderHMAC key(byte[] key) {
        this.key = key;
        return this;
    }

    /**
     * HMAC encryption method doesn`t support decryption
     */
    @Deprecated
    public String decrypt() {
        return super.decrypt();
    }

    @Deprecated
    public void decryptAsync() {
        return;
    }

    @Override
    String encryption() throws Exception {
        return HMAC.encrypt(method, key, message);
    }

    @Deprecated
    String decryption() throws Exception {
        throw new NoSuchMethodError();
    }

    @Override
    boolean hasEnoughData() {
        if(method == null){
            throw new NullPointerException(Constants.METHOD_EXCEPTION);
        }
        if(message == null){
            throw new NullPointerException(Constants.MESSAGE_EXCEPTION);
        }
        return true;
    }
}
