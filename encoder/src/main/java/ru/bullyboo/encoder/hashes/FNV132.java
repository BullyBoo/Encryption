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

package ru.bullyboo.encoder.hashes;

/**
 * The FNV132 Message-Digest Algorithm
 */

class FNV132 {

    private static final int FNV_32_PRIME = 0x01000193;

    public String getHash(String input){

        int hval = 0x811c9dc5;

        byte[] bytes = input.getBytes();

        int size = bytes.length;

        for (int i = 0; i < size; i++){
            hval *= FNV_32_PRIME;
            hval ^= bytes[i];

        }

        return getOutput(hval);
    }

    private String getOutput(int i){

        return Integer.toHexString(i);
    }

}
