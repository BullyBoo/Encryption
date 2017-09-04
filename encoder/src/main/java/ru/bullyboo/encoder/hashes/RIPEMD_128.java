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
 * The RIPEMD-128 Message-Digest Algorithm
 * (RACE Integrity Primitives Evaluation Message Digest)
 */
@SuppressWarnings("all")
class RIPEMD_128 {

    /**
     * Message Digest Buffer
     */
    private int A;
    private int B;
    private int C;
    private int D;

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
     *
     * A four-word buffer (A,B,C,D) is used to compute the message digest.
     * Here each of A, B, C, D is a 32-bit register. These registers are
     * initialized to the following values in hexadecimal, low-order bytes
     * first):
     *
     * word A: 01 23 45 67
     * word B: 89 ab cd ef
     * word C: fe dc ba 98
     * word D: 76 54 32 10
     *
     */
    private void initMdBuffer(){
        A = 0x67452301;
        B = 0xEFCDAB89;
        C = 0x98BADCFE;
        D = 0x10325476;
    }

    /**
     * Step 4. Process Message in 16-Word Blocks
     */
    private int[] processHash(int[] array){

        int AA, BB, CC, DD;
        int AAA, BBB, CCC, DDD;

        int[] x = new int[16];

        int length = array.length;

        for(int i = 0; i < length / 16; i++){

//            Copy block i into X
            System.arraycopy(array, i * 16, x, 0, 16);

//            init parameters
            AA = A;
            BB = B;
            CC = C;
            DD = D;
            AAA = A;
            BBB = B;
            CCC = C;
            DDD = D;

//            Round 1
//            Let [a b c d k s] denote the operation
//            a = (a + F(b,c,d) + X[k]) <<< s
//            Do the following 16 operations
            AA = FF(AA, BB, CC, DD, x[0],  11);
            DD = FF(DD, AA, BB, CC, x[1],  14);
            CC = FF(CC, DD, AA, BB, x[2],  15);
            BB = FF(BB, CC, DD, AA, x[3],  12);
            AA = FF(AA, BB, CC, DD, x[4],  5);
            DD = FF(DD, AA, BB, CC, x[5],  8);
            CC = FF(CC, DD, AA, BB, x[6],  7);
            BB = FF(BB, CC, DD, AA, x[7],  9);
            AA = FF(AA, BB, CC, DD, x[8],  11);
            DD = FF(DD, AA, BB, CC, x[9],  13);
            CC = FF(CC, DD, AA, BB, x[10], 14);
            BB = FF(BB, CC, DD, AA, x[11], 15);
            AA = FF(AA, BB, CC, DD, x[12], 6);
            DD = FF(DD, AA, BB, CC, x[13], 7);
            CC = FF(CC, DD, AA, BB, x[14], 9);
            BB = FF(BB, CC, DD, AA, x[15], 8);

//            Round 2
//            Let [a b c d k s] denote the operation
//            a = (a + G(b,c,d) + X[k] + 0x5A827999) <<< s
//            Do the following 16 operations
            AA = GG(AA, BB, CC, DD, x[7],  7);
            DD = GG(DD, AA, BB, CC, x[4],  6);
            CC = GG(CC, DD, AA, BB, x[13], 8);
            BB = GG(BB, CC, DD, AA, x[1],  13);
            AA = GG(AA, BB, CC, DD, x[10], 11);
            DD = GG(DD, AA, BB, CC, x[6],  9);
            CC = GG(CC, DD, AA, BB, x[15], 7);
            BB = GG(BB, CC, DD, AA, x[3],  15);
            AA = GG(AA, BB, CC, DD, x[12], 7);
            DD = GG(DD, AA, BB, CC, x[0],  12);
            CC = GG(CC, DD, AA, BB, x[9],  15);
            BB = GG(BB, CC, DD, AA, x[5],  9);
            AA = GG(AA, BB, CC, DD, x[2],  11);
            DD = GG(DD, AA, BB, CC, x[14], 7);
            CC = GG(CC, DD, AA, BB, x[11], 13);
            BB = GG(BB, CC, DD, AA, x[8],  12);

//            Round 3
//            Let [a b c d k s] denote the operation
//            a = (a + H(b,c,d) + X[k] + 0x6ED9EBA1) <<< s
//            Do the following 16 operations
            AA = HH(AA, BB, CC, DD, x[3],  11);
            DD = HH(DD, AA, BB, CC, x[10], 13);
            CC = HH(CC, DD, AA, BB, x[14], 6);
            BB = HH(BB, CC, DD, AA, x[4],  7);
            AA = HH(AA, BB, CC, DD, x[9],  14);
            DD = HH(DD, AA, BB, CC, x[15], 9);
            CC = HH(CC, DD, AA, BB, x[8],  13);
            BB = HH(BB, CC, DD, AA, x[1],  15);
            AA = HH(AA, BB, CC, DD, x[2],  14);
            DD = HH(DD, AA, BB, CC, x[7],  8);
            CC = HH(CC, DD, AA, BB, x[0],  13);
            BB = HH(BB, CC, DD, AA, x[6],  6);
            AA = HH(AA, BB, CC, DD, x[13], 5);
            DD = HH(DD, AA, BB, CC, x[11], 12);
            CC = HH(CC, DD, AA, BB, x[5],  7);
            BB = HH(BB, CC, DD, AA, x[12], 5);

//            Round 4
//            Let [a b c d k s] denote the operation
//            a = (a + I(b,c,d) + X[k] + 0x8F1BBCDC) <<< s
//            Do the following 16 operations
            AA = II(AA, BB, CC, DD, x[1],  11);
            DD = II(DD, AA, BB, CC, x[9],  12);
            CC = II(CC, DD, AA, BB, x[11], 14);
            BB = II(BB, CC, DD, AA, x[10], 15);
            AA = II(AA, BB, CC, DD, x[0],  14);
            DD = II(DD, AA, BB, CC, x[8],  15);
            CC = II(CC, DD, AA, BB, x[12], 9);
            BB = II(BB, CC, DD, AA, x[4],  8);
            AA = II(AA, BB, CC, DD, x[13], 9);
            DD = II(DD, AA, BB, CC, x[3],  14);
            CC = II(CC, DD, AA, BB, x[7],  5);
            BB = II(BB, CC, DD, AA, x[15], 6);
            AA = II(AA, BB, CC, DD, x[14], 8);
            DD = II(DD, AA, BB, CC, x[5],  6);
            CC = II(CC, DD, AA, BB, x[6],  5);
            BB = II(BB, CC, DD, AA, x[2],  12);

//            Parallel Round 1
//            Let [a b c d k s] denote the operation
//            a = (a + I(b,c,d) + X[k] + 0x50A28BE6) <<< s
//            Do the following 16 operations
            AAA = III(AAA, BBB, CCC, DDD, x[5],  8);
            DDD = III(DDD, AAA, BBB, CCC, x[14], 9);
            CCC = III(CCC, DDD, AAA, BBB, x[7],  9);
            BBB = III(BBB, CCC, DDD, AAA, x[0],  11);
            AAA = III(AAA, BBB, CCC, DDD, x[9],  13);
            DDD = III(DDD, AAA, BBB, CCC, x[2],  15);
            CCC = III(CCC, DDD, AAA, BBB, x[11], 15);
            BBB = III(BBB, CCC, DDD, AAA, x[4],  5);
            AAA = III(AAA, BBB, CCC, DDD, x[13], 7);
            DDD = III(DDD, AAA, BBB, CCC, x[6],  7);
            CCC = III(CCC, DDD, AAA, BBB, x[15], 8);
            BBB = III(BBB, CCC, DDD, AAA, x[8],  11);
            AAA = III(AAA, BBB, CCC, DDD, x[1],  14);
            DDD = III(DDD, AAA, BBB, CCC, x[10], 14);
            CCC = III(CCC, DDD, AAA, BBB, x[3],  12);
            BBB = III(BBB, CCC, DDD, AAA, x[12], 6);

//            Parallel Round 2
//            Let [a b c d k s] denote the operation
//            a = (a + H(b,c,d) + X[k] + 0x5C4DD124) <<< s
//            Do the following 16 operations
            AAA = HHH(AAA, BBB, CCC, DDD, x[6],  9);
            DDD = HHH(DDD, AAA, BBB, CCC, x[11], 13);
            CCC = HHH(CCC, DDD, AAA, BBB, x[3],  15);
            BBB = HHH(BBB, CCC, DDD, AAA, x[7],  7);
            AAA = HHH(AAA, BBB, CCC, DDD, x[0],  12);
            DDD = HHH(DDD, AAA, BBB, CCC, x[13], 8);
            CCC = HHH(CCC, DDD, AAA, BBB, x[5],  9);
            BBB = HHH(BBB, CCC, DDD, AAA, x[10], 11);
            AAA = HHH(AAA, BBB, CCC, DDD, x[14], 7);
            DDD = HHH(DDD, AAA, BBB, CCC, x[15], 7);
            CCC = HHH(CCC, DDD, AAA, BBB, x[8],  12);
            BBB = HHH(BBB, CCC, DDD, AAA, x[12], 7);
            AAA = HHH(AAA, BBB, CCC, DDD, x[4],  6);
            DDD = HHH(DDD, AAA, BBB, CCC, x[9],  15);
            CCC = HHH(CCC, DDD, AAA, BBB, x[1],  13);
            BBB = HHH(BBB, CCC, DDD, AAA, x[2],  11);

//            Parallel Round 3
//            Let [a b c d k s] denote the operation
//            a = (a + G(b,c,d) + X[k] + 0x6D703EF3) <<< s
//            Do the following 16 operations
            AAA = GGG(AAA, BBB, CCC, DDD, x[15], 9);
            DDD = GGG(DDD, AAA, BBB, CCC, x[5],  7);
            CCC = GGG(CCC, DDD, AAA, BBB, x[1],  15);
            BBB = GGG(BBB, CCC, DDD, AAA, x[3],  11);
            AAA = GGG(AAA, BBB, CCC, DDD, x[7],  8);
            DDD = GGG(DDD, AAA, BBB, CCC, x[14], 6);
            CCC = GGG(CCC, DDD, AAA, BBB, x[6],  6);
            BBB = GGG(BBB, CCC, DDD, AAA, x[9],  14);
            AAA = GGG(AAA, BBB, CCC, DDD, x[11], 12);
            DDD = GGG(DDD, AAA, BBB, CCC, x[8],  13);
            CCC = GGG(CCC, DDD, AAA, BBB, x[12], 5);
            BBB = GGG(BBB, CCC, DDD, AAA, x[2],  14);
            AAA = GGG(AAA, BBB, CCC, DDD, x[10], 13);
            DDD = GGG(DDD, AAA, BBB, CCC, x[0],  13);
            CCC = GGG(CCC, DDD, AAA, BBB, x[4],  7);
            BBB = GGG(BBB, CCC, DDD, AAA, x[13], 5);

//            Parallel Round 4
//            Let [a b c d k s] denote the operation
//            a = (a + F(b,c,d) + X[k]) <<< s
//            Do the following 16 operations
            AAA = FFF(AAA, BBB, CCC, DDD, x[8],  15);
            DDD = FFF(DDD, AAA, BBB, CCC, x[6],  5);
            CCC = FFF(CCC, DDD, AAA, BBB, x[4],  8);
            BBB = FFF(BBB, CCC, DDD, AAA, x[1],  11);
            AAA = FFF(AAA, BBB, CCC, DDD, x[3],  14);
            DDD = FFF(DDD, AAA, BBB, CCC, x[11], 14);
            CCC = FFF(CCC, DDD, AAA, BBB, x[15], 6);
            BBB = FFF(BBB, CCC, DDD, AAA, x[0],  14);
            AAA = FFF(AAA, BBB, CCC, DDD, x[5],  6);
            DDD = FFF(DDD, AAA, BBB, CCC, x[12], 9);
            CCC = FFF(CCC, DDD, AAA, BBB, x[2],  12);
            BBB = FFF(BBB, CCC, DDD, AAA, x[13], 9);
            AAA = FFF(AAA, BBB, CCC, DDD, x[9],  12);
            DDD = FFF(DDD, AAA, BBB, CCC, x[7],  5);
            CCC = FFF(CCC, DDD, AAA, BBB, x[10], 15);
            BBB = FFF(BBB, CCC, DDD, AAA, x[14], 8);

//            Converting result
            DDD = B + CC + DDD;
            B = C + DD + AAA;
            C = D + AA + BBB;
            D = A + BB + CCC;
            A = DDD;
        }

        return new int[]{A, B, C, D};
    }

    /**
     * F(X,Y,Z) = X xor Y xor Z
     */
    private int F(int x, int y, int z){
        return ((x) ^ (y) ^ (z));
    }

    /**
     * G(X,Y,Z) = XY v not XZ
     */
    private int G(int x, int y, int z){
        return (((x) & (y)) | ((~(x)) & (z)));
    }

    /**
     * H(X,Y,Z) = X v not Y v xor Z
     */
    private int H(int x, int y, int z){
        return (((x) | (~(y))) ^ (z));
    }

    /**
     * I(X,Y,Z) = XZ or Y not Z
     */
    private int I(int x, int y, int z){
        return (((x) & (z)) | ((y) & (~(z))));
    }

    /**
     * Round 1
     */
    private int FF(int a, int b, int c, int d, int x, int s){
        a += F(b, c, d) + (x);
        return rol(a, s);
    }

    /**
     * Round 2
     */
    private int GG(int a, int b, int c, int d, int x, int s){
        a += G(b, c, d) + (x) + 0x5A827999;
        return rol(a, s);
    }

    /**
     * Round 3
     */
    private int HH(int a, int b, int c, int d, int x, int s){
        a += H(b, c, d) + (x) + 0x6ED9EBA1;
        return rol(a, s);
    }

    /**
     * Round 4
     */
    private int II(int a, int b, int c, int d, int x, int s){
        a += I(b, c, d) + (x) + 0x8F1BBCDC;
        return rol(a, s);
    }

    /**
     * Parallel Round 4
     */
    private int FFF(int a, int b, int c, int d, int x, int s){
        a += F(b, c, d) + (x);
        return rol(a, s);
    }

    /**
     * Parallel Round 3
     */
    private int GGG(int a, int b, int c, int d, int x, int s){
        a += G(b, c, d) + (x) + 0x6D703EF3;
        return rol(a, s);
    }

    /**
     * Parallel Round 2
     */
    private int HHH(int a, int b, int c, int d, int x, int s){
        a += H(b, c, d) + (x) + 0x5C4DD124;
        return rol(a, s);
    }

    /**
     * Parallel Round 1
     */
    private int III(int a, int b, int c, int d, int x, int s){
        a += I(b, c, d) + (x) + 0x50A28BE6;
        return rol(a, s);
    }

    private int rol(int x, int y){
        return ((x)<<(y))|((x)>>>(32-y));
    }

    /**
     * Method for converting A, B, C, D params to hex for getting hash
     */
    private String getOutput(int[] array){
        StringBuilder hexString = new StringBuilder();

        for(int i = 0; i < 4; i++){
            String h = Integer.toHexString(changeEndianness(array[i]));
            hexString.append(h);
        }

        return hexString.toString();
    }

    private int changeEndianness(int x){
        return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >>> 8) | ((x & 0xFF000000) >>> 24);
    }

}

