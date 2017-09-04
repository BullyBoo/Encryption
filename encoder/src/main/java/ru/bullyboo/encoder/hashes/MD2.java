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

import ru.bullyboo.encoder.utils.ArrayUtils;

/**
 * The MD2 Message-Digest Algorithm
 */

class MD2 {

    /**
     * substitution table derived from Pi. Copied from the RFC.
     */
    private final static int[] S = new int[] {
            41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
            98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
            30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
            190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
            169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
            128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
            255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
            79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
            69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
            27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
            85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
            44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
            106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
            120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
            242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
            49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20};

    /**
     * MD Buffer
     */
    private int[] x;

    /**
     * This method return hash of message
     */
    public byte[] getHash(String message){

        int[] messageInt = appendPaddingBytes(message.getBytes());
        messageInt = appendCheckSum(messageInt);

        initMdBuffer();

        int[] x = processMessage(messageInt);

        return getOutput(x);
    }

    /**
     * Step 1. Append Padding Bytes
     *
     * The message is "padded" (extended) so that its length (in bytes) is
     * congruent to 0, modulo 16. That is, the message is extended so that
     * it is a multiple of 16 bytes long. Padding is always performed, even
     * if the length of the message is already congruent to 0, modulo 16.
     *
     * Padding is performed as follows: "i" bytes of value "i" are appended
     * to the message so that the length in bytes of the padded message
     * becomes congruent to 0, modulo 16. At least one byte and at most 16
     * 16 bytes are appended.
     *
     * At this point the resulting message (after padding with bytes) has a
     * length that is an exact multiple of 16 bytes. Let M[0 ... N-1] denote
     * the bytes of the resulting message, where N is a multiple of 16.
     *
     * Copied from RFC 1319
     * Page 1
     * https://tools.ietf.org/html/rfc1319
     *
     */
    private int[] appendPaddingBytes(byte[] bytes){

        int size = bytes.length;

        int temp = size;

        do{
            temp++;
        } while (temp % 16 != 0);

        int value = temp - size;

        int[] paddingBytes = new int[value];

        for(int i = 0; i < value ; i++){
            paddingBytes[i] = value;
        }

        return ArrayUtils.mergeArrays(bytes, paddingBytes);
    }

    /**
     * Step 2. Append Checksum
     *
     * A 16-byte checksum of the message is appended to the result of the
     * previous step.
     *
     * This step uses a 256-byte "random" permutation constructed from the
     * digits of pi. Let S[i] denote the i-th element of this table. The
     * table is given in the appendix.
     *
     * The 16-byte checksum C[0 ... 15] is appended to the message. Let M[0
     * with checksum), where N' = N + 16.
     *
     * Copied from RFC 1319
     * Page 2
     * https://tools.ietf.org/html/rfc1319
     *
     */
    private int[] appendCheckSum(int[] bytes){

        int[] checkSum = new int[16];

        int size = checkSum.length;

        int L = 0;

        for(int i = 0; i < size/16; i++){

            for(int j = 0; j < 16; j++){

                int c = bytes[i * 16 + j];
                int s = S[c^L];
                L = checkSum[j] ^ s;
                checkSum[j] = L;
            }
        }

        return ArrayUtils.mergeArrays(bytes, checkSum);
    }

    /**
     * Step 3. Initialize MD Buffer
     *
     * A 48-byte buffer X is used to compute the message digest. The buffer
     * is initialized to zero.
     *
     * Copied from RFC 1319
     * Page 3
     * https://tools.ietf.org/html/rfc1319
     *
     */
    private int[] initMdBuffer() {
        x = new int[48];
        return x;
    }

    /**
     * Step 4. Process Message in 16-Byte Blocks
     *
     * This step uses the same 256-byte permutation S as step 2 does.
     *
     * Copied from RFC 1319
     * Page 4
     * https://tools.ietf.org/html/rfc1319
     *
     */
    private int[] processMessage(int[] array){

        int size = array.length;

        for(int i = 0; i < size/16; i++){

//            copy block i into x
            for(int j = 0; j < 16; j++){
                x[16 + j] = array[i * 16 + j];
                x[32 + j] = x[16 + j] ^ x[j];
            }

            int t = 0;

//            18 rounds
            for(int j = 0; j < 18; j++){

//                round j
                for(int k = 0; k < 48; k++){
                    x[k] = x[k] ^ S[t];
                    t = x[k];
                }

                t = (t+j) % 256;
            }
        }

        return x;
    }

    /**
     * Step 5. Output
     *
     * The message digest produced as output is X[0 ... 15]. That is, we
     * begin with X[0], and end with X[15].
     *
     * This completes the description of MD2. A reference implementation in
     * C is given in the appendix.
     *
     * Copied from RFC 1319
     * Page 4
     * https://tools.ietf.org/html/rfc1319
     *
     */
    private byte[] getOutput(int[] x) {
        byte[] hash = new byte[16];

        for(int i = 0; i < 16; i++){
            hash[i] = (byte) x[i];
        }
        return hash;
    }
}
