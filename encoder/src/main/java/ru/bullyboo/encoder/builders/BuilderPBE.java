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
import ru.bullyboo.encoder.methods.PBE;

/**
 * PBE Encrypt/Decrypt Builder
 */
public class BuilderPBE extends BaseBuilder<BuilderPBE>{

    private volatile PBE.Method method;

    private volatile byte[] key = new byte[]{};
    private volatile PBE.KeySize keySize;

    private volatile byte[] vector = new byte[]{};

    /**
     * Set the encryption method for encrypting or decrypting
     */
    public BuilderPBE method(PBE.Method method) {
        this.method = method;
        return this;
    }

    /**
     * Set the encryption key and its bite size
     */
    public BuilderPBE key(String key, PBE.KeySize keySize) {
        this.key = key.getBytes();
        this.keySize = keySize;
        return this;
    }

    public BuilderPBE key(String key) {
        this.key = key.getBytes();
        return this;
    }

    public BuilderPBE key(byte[]  key) {
        this.key = key;
        return this;
    }

    public BuilderPBE key(byte[] key, PBE.KeySize keySize) {
        this.key = key;
        this.keySize = keySize;
        return this;
    }

    public BuilderPBE keySize(PBE.KeySize keySize) {
        this.keySize = keySize;
        return this;
    }

    /**
     * Set initialization vector (IV)
     */
    public BuilderPBE iVector(String vector) {
        this.vector = vector.getBytes();
        return this;
    }

    public BuilderPBE iVector(byte[] vector) {
        this.vector = vector;
        return this;
    }

    @Override
    String encryption() throws Exception {
        return PBE.encrypt(method, key, keySize, vector, message);
    }

    @Override
    String decryption() throws Exception {
        return PBE.decrypt(method, key, keySize, vector, message);
    }

    @Override
    boolean hasEnoughData() {
        if (!methodHasKeySize()) {
            throw new IllegalStateException(Constants.PBE_KEY_SIZE_EXCEPTION + getAllSizes());
        }
        if (method == null) {
            throw new NullPointerException(Constants.METHOD_EXCEPTION);
        }
        if (message == null) {
            throw new NullPointerException(Constants.MESSAGE_EXCEPTION);
        }

        return true;
    }

    /**
     * Check whether the set keysize is support by the chosen encryption method
     */
    private boolean methodHasKeySize(){
        if(keySize == null){
            keySize = PBE.setKeySize(method.getKeySizes()[0]);
        }

        int keySize = this.keySize.getSize();

        int[] sizes = method.getKeySizes();

        for(int size : sizes){
            if(keySize == size){
                return true;
            }
        }
        return false;
    }

    /**
     * Getting all supported keysizes by the chosen encryption method
     * It`  s needed for showing at logs.
     */
    private String getAllSizes(){
        String result = "";

        int[] sizes = method.getKeySizes();

        for(int i = 0; i < sizes.length; i++){
            if(i+1 != sizes.length){
                result += sizes[i] + ", ";
            } else {
                result += sizes[i];
            }
        }
        return result;
    }
}
