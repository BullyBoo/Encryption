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


import java.util.ArrayList;
import java.util.List;

import ru.bullyboo.encoder.utils.ArrayUtils;

/**
 * The SHA1 Message-Digest Algorithm
 */
class SHA1 {

    /**
     * Message Digest Buffer
     */
    private int A;
    private int B;
    private int C;
    private int D;
    private int E;

    /**
     * This method return hash of message
     */
    public String getHash(String input){

        byte[] bytes = input.getBytes();

        List<Integer> intList = appendPaddingBits(bytes);

        intList = appendLength(intList, bytes.length * 8);

        int[] array = ArrayUtils.convertListToArray(intList);

        initMdBuffer();

        array = processHash(array);

        return getOutput(array);
    }

    /**
     * Step 1. Append Padding Bits
     *
     * The message is "padded" (extended) so that its length (in bits) is
     * congruent to 448, modulo 512. That is, the message is extended so
     * that it is just 64 bits shy of being a multiple of 512 bits long.
     * Padding is always performed, even if the length of the message is
     * already congruent to 448, modulo 512.
     *
     * Padding is performed as follows: a single "1" bit is appended to the
     * message, and then "0" bits are appended so that the length in bits of
     * the padded message becomes congruent to 448, modulo 512. In all, at
     * least one bit and at most 512 bits are appended.
     *
     */
    private List<Integer> appendPaddingBits(byte[] bytes){
        List<Integer> intList = new ArrayList<>();

        for (byte aByte : bytes) {
            intList.add((int) aByte);
        }

        int one = 128;
        int zero = 0;

        intList.add(one);

        while (intList.size() % 64 != 56){
            intList.add(zero);
        }

        return intList;
    }

    /**
     * Step 2. Append Length
     *
     * A 64-bit representation of b (the length of the message before the
     * padding bits were added) is appended to the result of the previous
     * step. In the unlikely event that b is greater than 2^64, then only
     * the low-order 64 bits of b are used. (These bits are appended as two
     * 32-bit words and appended low-order word first in accordance with the
     * previous conventions.)
     *
     * At this point the resulting message (after padding with bits and with
     * b) has a length that is an exact multiple of 512 bits. Equivalently,
     * this message has a length that is an exact multiple of 16 (32-bit)
     * words. Let M[0 ... N-1] denote the words of the resulting message,
     * where N is a multiple of 16.
     *
     */
    private List<Integer> appendLength(List<Integer> intList, int length){
        List<Integer> integers = new ArrayList<>();


        for (int i = 0; i < intList.size(); i += 4) {
            integers.add(intList.get(i) | intList.get(i + 1) << 8 | intList.get(i + 2) << 16 | intList.get(i + 3) << 24);
        }

        integers.add(length);
        integers.add(0);

        return integers;
    }

    /**
     * Step 3. Initialize MD Buffer
     *f
     * A four-word buffer (A,B,C,D) is used to compute the message digest.
     * Here each of A, B, C, D is a 32-bit register. These registers are
     * initialized to the following values in hexadecimal, low-order bytes
     * first):
     *
     * word A: 01 23 45 67
     * word B: 89 ab cd ef
     * word C: fe dc ba 98
     * word D: 76 54 32 10
     * word E: 0f e1 d2 c3
     */
    private void initMdBuffer(){
        A = 0x67452301;
        B = 0xefcdab89;
        C = 0x98badcfe;
        D = 0x10325476;
        E = 0xc3d2e1f0;
    }

    /**
     * Step 4. Process Message in 16-Word Blocks
     */
    private int[] processHash(int[] array){

        int AA, BB, CC, DD, EE;

        int[] x = new int[80];

        int length = array.length;

//        Process each 16-word block
        for(int i = 0; i < length / 16; i++){

//            Copy block i into X
            System.arraycopy(array, i * 16, x, 0, 16);

            for(int k = 0; k < 16; k++){
                x[k] = changeEndianness(array[i*16 + k]);
            }

            for(int k = 16; k < 80; k++){
                x[k] = rol(x[k-3] ^ x[k-8] ^ x[k-14] ^ x[k-16], 1);
            }

//            Save A as AA, B as BB, C as CC, and D as DD
            AA = A;
            BB = B;
            CC = C;
            DD = D;
            EE = E;

            for(int j = 0; j < 80; j++){
                int T = FF(j, AA, BB, CC, DD, EE, x[j]);
                EE = DD;
                DD = CC;
                CC = rol(BB, 30);
                BB = AA;
                AA = T;
            }

//            Then perform the following additions. (That is increment each
//            of the four registers by the value it had before this block
//            was started.)
            A += AA;
            B += BB;
            C += CC;
            D += DD;
            E += EE;
        }

        return new int[]{A, B, C, D, E};
    }

    /**
     * Boolean functions for rounds
     */
    private int F(int x, int y, int z, int i){
        if(i >= 0 && i <= 19){
            return (x & y) | (~x & z);

        } else if(i >= 20 && i <= 39){
            return x ^ y ^ z;

        } else if (i >= 40 && i <= 59){
            return (x & y) | (x & z) | (y & z);

        } else if(i >= 60 && i <= 79){
            return x ^ y ^ z;

        } else {
            return 0;
        }
    }

    /**
     * Round
     */
    private int FF(int i, int a, int b, int c, int d, int e, int x){
        a = rol(a,5) +  F(b, c, d, i) + e + (x);

        if(i >= 0 && i <= 19){
            a += 0x5A827999;

        } else if(i >= 20 && i <= 39){
            a += 0x6ED9EBA1;

        } else if (i >= 40 && i <= 59){
            a += 0x8F1BBCDC;

        } else if (i >= 60 && i <= 79){
            a += 0xCA62C1D6;
        }
        return a;
    }

    private int rol(int x, int y){
        return ((x)<<(y))|((x)>>>(32-y));
    }

    /**
     * Method for converting A, B, C, D, E params to hex for getting hash
     */
    private String getOutput(int[] array){
        StringBuilder hexString = new StringBuilder();

        for(int i = 0; i < 5; i++){
            String h = Integer.toHexString(array[i]);
            hexString.append(h);
        }

        return hexString.toString();
    }

    private int changeEndianness(int x){
        return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >>> 8) | ((x & 0xFF000000) >>> 24);
    }
}
