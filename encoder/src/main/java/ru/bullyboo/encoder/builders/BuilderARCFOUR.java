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
import ru.bullyboo.encoder.methods.ARCFOUR;

/**
 * ARCFOUR Encrypt/Decrypt Builder
 */
public class BuilderARCFOUR extends BaseBuilder<BuilderARCFOUR>{

    private volatile byte[] key = new byte[]{};
    private volatile int keySize = 1;

    /**
     * Set the encryption key and its bite size
     * Can`t be equals to 0
     * Can`t be less than 0
     */
    public BuilderARCFOUR key(String key) {
        this.key = key.getBytes();
        return this;
    }

    public BuilderARCFOUR key(String key, int keySize) {
        this.key = key.getBytes();
        this.keySize = keySize;
        return this;
    }

    public BuilderARCFOUR key(byte[] key, int keySize) {
        this.key = key;
        this.keySize = keySize;
        return this;
    }

    public BuilderARCFOUR keySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    @Override
    String encryption() throws Exception {
        return ARCFOUR.encrypt(key, keySize, message);
    }

    @Override
    String decryption() throws Exception {
        return ARCFOUR.decrypt(key, keySize, message);
    }

    @Override
    boolean hasEnoughData() {
        if(message == null){
            throw new NullPointerException(Constants.MESSAGE_EXCEPTION);
        }
        if(keySize == 0){
            throw new IllegalArgumentException(Constants.KEY_SIZE_EXCEPTION);
        } else if (keySize < 0){
            throw new IllegalArgumentException(Constants.LESS_ZERO_KEY_SIZE_EXCEPTION);
        }
        return true;
    }
}
