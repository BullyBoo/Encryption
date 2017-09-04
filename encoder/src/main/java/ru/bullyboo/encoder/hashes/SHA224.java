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
 * The SHA224 Message-Digest Algorithm
 */
class SHA224 {

    private static final int[] K = {
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };

    /**
     * Message Digest Buffer
     */
    private int A;
    private int B;
    private int C;
    private int D;
    private int E;
    private int F;
    private int G;
    private int H;

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
     * word A: D8 9E 05 C1
     * word B: 07 D5 7C 36
     * word C: 17 DD 70 30
     * word D: 39 59 0E F7
     * word E: 31 0B C0 FF
     * word F: 11 15 58 68
     * word G: A7 8F F9 64
     * word H: A4 4F FA BE
     */
    private void initMdBuffer(){
        A = 0xC1059ED8;
        B = 0x367CD507;
        C = 0x3070DD17;
        D = 0xF70E5939;
        E = 0xFFC00B31;
        F = 0x68581511;
        G = 0x64F98FA7;
        H = 0xBEFA4FA4;
    }

    /**
     * Step 4. Process Message in 16-Word Blocks
     */
    private int[] processHash(int[] array){

        int AA, BB, CC, DD, EE, FF, GG, HH;

        int[] x = new int[64];

        int length = array.length;

//        Process each 16-word block
        for(int i = 0; i < length / 16; i++){

//            Copy block i into X
            System.arraycopy(array, i * 16, x, 0, 16);

            for(int k = 0; k < 16; k++){
                x[k] = changeEndianness(array[i*16 + k]);
            }

            for(int k = 16; k < 64; k++){
                int s0  = rolR(x[k-15], 7) ^ rolR(x[k-15], 18) ^ (x[k-15] >>> 3);
                int s1 = rolR(x[k-2], 17) ^ rolR(x[k-2], 19) ^ (x[k-2] >>> 10);
                x[k] = x[k-16] + s0 + x[k-7] + s1;
            }

//            Save A as AA, B as BB, C as CC, and D as DD
            AA = A;
            BB = B;
            CC = C;
            DD = D;
            EE = E;
            FF = F;
            GG = G;
            HH = H;

            for(int j = 0; j < 64; j++){
                int z0 = rolR(AA, 2) ^ rolR(AA, 13) ^ rolR(AA, 22);
                int Ma = (AA & BB) ^ (AA & CC) ^ (BB & CC);
                int t2 = z0 + Ma;
                int z1 = rolR(EE, 6) ^ rolR(EE, 11) ^ rolR(EE, 25);
                int Ch = (EE & FF) ^ (~EE & GG);
                int t1 = HH + z1 + Ch + K[j] + x[j];

                HH = GG;
                GG = FF;
                FF = EE;
                EE = DD + t1;
                DD = CC;
                CC = BB;
                BB = AA;
                AA = t1 + t2;
            }

//            Then perform the following additions. (That is increment each
//            of the four registers by the value it had before this block
//            was started.)
            A += AA;
            B += BB;
            C += CC;
            D += DD;
            E += EE;
            F += FF;
            G += GG;
            H += HH;
        }

        return new int[]{A, B, C, D, E, F, G, H};
    }

    private int rolR(int x, int y){
        return ((x)>>>(y))|((x)<<(32-y));
    }

    /**
     * Method for converting A, B, C, D, E, F, G, H params to hex for getting hash
     */
    private String getOutput(int[] array){
        StringBuilder hexString = new StringBuilder();

        for(int i = 0; i < 7; i++){
            String h = Integer.toHexString(array[i]);
            hexString.append(h);
        }

        return hexString.toString();
    }

    private int changeEndianness(int x){
        return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >>> 8) | ((x & 0xFF000000) >>> 24);
    }
}
