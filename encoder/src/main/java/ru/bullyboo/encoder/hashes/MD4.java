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
 * The MD4 Message-Digest Algorithm
 */

class MD4 {

    /**
     * MD Buffer
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
     * Copied from RFC 1320
     * Page 3
     * https://tools.ietf.org/html/rfc1320
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
     * Copied from RFC 1320
     * Page 3
     * https://tools.ietf.org/html/rfc1320
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
     * Copied from RFC 1320
     * Page 3
     * https://tools.ietf.org/html/rfc1320
     *
     */
    private void initMdBuffer(){
        A = 0x67452301;
        B = 0xefcdab89;
        C = 0x98badcfe;
        D = 0x10325476;
    }

    /**
     * Step 4. Process Message in 16-Word Blocks
     *
     * We first define three auxiliary functions that each take as input
     * three 32-bit words and produce as output one 32-bit word.
     *
     * F(X,Y,Z) = XY v not(X) Z
     * G(X,Y,Z) = XY v XZ v YZ
     * H(X,Y,Z) = X xor Y xor Z
     *
     * In each bit position F acts as a conditional: if X then Y else Z.
     * The function F could have been defined using + instead of v since XY
     * and not(X)Z will never have "1" bits in the same bit position.)  In
     * each bit position G acts as a majority function: if at least two of
     * X, Y, Z are on, then G has a "1" bit in that bit position, else G has
     * a "0" bit. It is interesting to note that if the bits of X, Y, and Z
     * are independent and unbiased, the each bit of f(X,Y,Z) will be
     * independent and unbiased, and similarly each bit of g(X,Y,Z) will be
     * independent and unbiased. The function H is the bit-wise XOR or
     * parity" function; it has properties similar to those of F and G.
     *
     * Copied from RFC 1320
     * Page 4
     * https://tools.ietf.org/html/rfc1320
     *
     */
    @SuppressWarnings("all")
    private int[] processHash(int[] array){
        int AA, BB, CC, DD;

        int[] x = new int[16];

        int length = array.length;

//        Process each 16-word block
        for(int i = 0; i < length / 16; i++){

//            Copy block i into X
            System.arraycopy(array, i * 16, x, 0, 16);

//            Save A as AA, B as BB, C as CC, and D as DD
            AA=A;
            BB=B;
            CC=C;
            DD=D;

//            Round 1
//            Let [abcd k s] denote the operation
//            a = (a + F(b,c,d) + X[k]) <<< s
//            Do the following 16 operations
            A = FF(A,B,C,D,x[0],3);
            D = FF(D,A,B,C,x[1],7);
            C = FF(C,D,A,B,x[2],11);
            B = FF(B,C,D,A,x[3],19);
            A = FF(A,B,C,D,x[4],3);
            D = FF(D,A,B,C,x[5],7);
            C = FF(C,D,A,B,x[6],11);
            B = FF(B,C,D,A,x[7],19);
            A = FF(A,B,C,D,x[8],3);
            D = FF(D,A,B,C,x[9],7);
            C = FF(C,D,A,B,x[10],11);
            B = FF(B,C,D,A,x[11],19);
            A = FF(A,B,C,D,x[12],3);
            D = FF(D,A,B,C,x[13],7);
            C = FF(C,D,A,B,x[14],11);
            B = FF(B,C,D,A,x[15],19);

//            Round 2
//            Let [abcd k s] denote the operation
//            a = (a + G(b,c,d) + X[k] + 5A827999) <<< s
//            Do the following 16 operations
            A = GG(A,B,C,D,x[0],3);
            D = GG(D,A,B,C,x[4],5);
            C = GG(C,D,A,B,x[8],9);
            B = GG(B,C,D,A,x[12],13);
            A = GG(A,B,C,D,x[1],3);
            D = GG(D,A,B,C,x[5],5);
            C = GG(C,D,A,B,x[9],9);
            B = GG(B,C,D,A,x[13],13);
            A = GG(A,B,C,D,x[2],3);
            D = GG(D,A,B,C,x[6],5);
            C = GG(C,D,A,B,x[10],9);
            B = GG(B,C,D,A,x[14],13);
            A = GG(A,B,C,D,x[3],3);
            D = GG(D,A,B,C,x[7],5);
            C = GG(C,D,A,B,x[11],9);
            B = GG(B,C,D,A,x[15],13);

//            Round 3
//            Let [abcd k s] denote the operation
//            a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s
//            Do the following 16 operations
            A = HH(A,B,C,D,x[0],3);
            D = HH(D,A,B,C,x[8],9);
            C = HH(C,D,A,B,x[4],11);
            B = HH(B,C,D,A,x[12],15);
            A = HH(A,B,C,D,x[2],3);
            D = HH(D,A,B,C,x[10],9);
            C = HH(C,D,A,B,x[6],11);
            B = HH(B,C,D,A,x[14],15);
            A = HH(A,B,C,D,x[1],3);
            D = HH(D,A,B,C,x[9],9);
            C = HH(C,D,A,B,x[5],11);
            B = HH(B,C,D,A,x[13],15);
            A = HH(A,B,C,D,x[3],3);
            D = HH(D,A,B,C,x[11],9);
            C = HH(C,D,A,B,x[7],11);
            B = HH(B,C,D,A,x[15],15);

//            Then perform the following additions. (That is, increment each
//            of the four registers by the value it had before this block
//            was started
            A+=AA;
            B+=BB;
            C+=CC;
            D+=DD;
        }

        return new int[]{A, B, C, D};
    }

    /**
     * F(X,Y,Z) = XY v not(X) Z
     *
     * Copied from RFC 1320
     * Page 4
     * https://tools.ietf.org/html/rfc1320
     *
     */
    private int F(int x, int y, int z){
        return (((x)&(y))|((~(x))&(z)));
    }

    /**
     * G(X,Y,Z) = XY v XZ v YZ
     *
     * Copied from RFC 1320
     * Page 4
     * https://tools.ietf.org/html/rfc1320
     *
     */
    private int G(int x, int y, int z){
        return (((x)&(y))|((x)&(z))|((y)&(z)));
    }

    /**
     * H(X,Y,Z) = X xor Y xor Z
     *
     * Copied from RFC 1320
     * Page 4
     * https://tools.ietf.org/html/rfc1320
     *
     */
    private int H(int x, int y, int z){
        return ((x)^(y)^(z));
    }

    /**
     * Round 1
     */
    private int FF(int a, int b, int c, int d, int x, int s){
        a += F(b, c, d) + x;
        return rol(a ,s);
    }

    /**
     *
     * Round 2
     * Note. The value 5A..99 is a hexadecimal 32-bit constant, written with
     * the high-order digit first. This constant represents the square root
     * of 2. The octal value of this constant is 013240474631.
     *
     * Copied from RFC 1320
     * Page 5
     * https://tools.ietf.org/html/rfc1320
     *
     */
    private int GG(int a, int b, int c, int d, int x, int s){
        a += G(b, c, d) + x + 0x5A827999;
        return rol(a ,s);
    }

    /**
     * Round 3
     * The value 6E..A1 is a hexadecimal 32-bit constant, written with the
     * high-order digit first.  This constant represents the square root of
     * 3. The octal value of this constant is 015666365641.
     *
     * Copied from RFC 1320
     * Page 5
     * https://tools.ietf.org/html/rfc1320
     *
     */
    private int HH(int a, int b, int c, int d, int x, int s){
        a += H(b, c, d) + x + 0x6ED9EBA1;
        return rol(a ,s);
    }

    private int rol(int x, int y){
        return ((x)<<(y))|((x)>>>(32-y));
    }

    /**
     * The message digest produced as output is A, B, C, D. That is, we
     * begin with the low-order byte of A, and end with the high-order byte
     * of D.
     *
     * This completes the description of MD4. A reference implementation in
     * C is given in the appendix.
     *
     * Copied from RFC 1320
     * Page 5
     * https://tools.ietf.org/html/rfc1320
     *
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
