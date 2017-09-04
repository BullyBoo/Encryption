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
 * The MD5 Message-Digest Algorithm
 */
class MD5 {

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
     * Copied from RFC 1321
     * Page 3
     * https://tools.ietf.org/html/rfc1321
     *
     */
    private List<Integer> appendPaddingBits(byte[] bytes){
        List<Integer> intList = new ArrayList<>();

        for (byte aByte : bytes) {
            intList.add((int) aByte);
        }

        int one = 0x80;
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
     * Copied from RFC 1321
     * Page 3
     * https://tools.ietf.org/html/rfc1321
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
     * Copied from RFC 1321
     * Page 3 - 4
     * https://tools.ietf.org/html/rfc1321
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
     * We first define four auxiliary functions that each take as input
     * three 32-bit words and produce as output one 32-bit word.
     *
     * F(X,Y,Z) = XY v not(X) Z
     * G(X,Y,Z) = XZ v Y not(Z)
     * H(X,Y,Z) = X xor Y xor Z
     * I(X,Y,Z) = Y xor (X v not(Z))
     *
     * In each bit position F acts as a conditional: if X then Y else Z.
     * The function F could have been defined using + instead of v since XY
     * and not(X)Z will never have 1's in the same bit position.) It is
     * interesting to note that if the bits of X, Y, and Z are independent
     * and unbiased, the each bit of F(X,Y,Z) will be independent and
     * unbiased.
     *
     * The functions G, H, and I are similar to the function F, in that they
     * act in "bitwise parallel" to produce their output from the bits of X,
     * Y, and Z, in such a manner that if the corresponding bits of X, Y,
     * and Z are independent and unbiased, then each bit of G(X,Y,Z),
     * H(X,Y,Z), and I(X,Y,Z) will be independent and unbiased. Note that
     * the function H is the bit-wise "xor" or "parity" function of its
     * inputs.
     *
     * This step uses a 64-element table T[1 ... 64] constructed from the
     * sine function. Let T[i] denote the i-th element of the table, which
     * is equal to the integer part of 4294967296 times abs(sin(i)), where i
     * is in radians. The elements of the table are given in the appendix.
     *
     * Copied from RFC 1321
     * Page 4
     * https://tools.ietf.org/html/rfc1321
     *
     */
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

//            Round 1.
//            Let [abcd k s i] denote the operation
//            a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s).
//            Do the following 16 operations.
            A = FF(A, B, C, D, x[0], 7, 0xd76aa478);
            D = FF(D, A, B, C, x[1], 12, 0xe8c7b756);
            C = FF(C, D, A, B, x[2], 17, 0x242070db);
            B = FF(B, C, D, A, x[3], 22, 0xc1bdceee);
            A = FF(A, B, C, D, x[4], 7,0xf57c0faf);
            D = FF(D, A, B, C, x[5], 12,0x4787c62a);
            C = FF(C, D, A, B, x[6], 17, 0xa8304613);
            B = FF(B, C, D, A, x[7], 22, 0xfd469501);
            A = FF(A, B, C, D, x[8], 7, 0x698098d8);
            D = FF(D, A, B, C, x[9], 12, 0x8b44f7af);
            C = FF(C, D, A, B, x[10], 17, 0xffff5bb1);
            B = FF(B, C, D, A, x[11], 22, 0x895cd7be);
            A = FF(A, B, C, D, x[12], 7, 0x6b901122);
            D = FF(D, A, B, C, x[13], 12, 0xfd987193);
            C = FF(C, D, A, B, x[14], 17, 0xa679438e);
            B = FF(B, C, D, A, x[15], 22, 0x49b40821);

//            Round 2.
//            Let [abcd k s i] denote the operation
//            a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s).
//            Do the following 16 operations.
            A = GG(A, B, C, D, x[1], 5 , 0xf61e2562);
            D = GG(D, A, B, C, x[6], 9, 0xc040b340);
            C = GG(C, D, A, B, x[11], 14, 0x265e5a51);
            B = GG(B, C, D, A, x[0], 20, 0xe9b6c7aa);
            A = GG(A, B, C, D, x[5], 5 ,0xd62f105d);
            D = GG(D, A, B, C, x[10], 9, 0x2441453);
            C = GG(C, D, A, B, x[15], 14, 0xd8a1e681);
            B = GG(B, C, D, A, x[4], 20, 0xe7d3fbc8);
            A = GG(A, B, C, D, x[9], 5, 0x21e1cde6);
            D = GG(D, A, B, C, x[14], 9, 0xc33707d6);
            C = GG(C, D, A, B, x[3], 14, 0xf4d50d87);
            B = GG(B, C, D, A, x[8], 20, 0x455a14ed);
            A = GG(A, B, C, D, x[13], 5, 0xa9e3e905);
            D = GG(D, A, B, C, x[2], 9, 0xfcefa3f8);
            C = GG(C, D, A, B, x[7], 14, 0x676f02d9);
            B = GG(B, C, D, A, x[12], 20, 0x8d2a4c8a);

//            Round 3.
//            Let [abcd k s t] denote the operation
//            a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s).
//            Do the following 16 operations.
            A = HH(A, B, C, D, x[5], 4, 0xfffa3942);
            D = HH(D, A, B, C, x[8], 11, 0x8771f681);
            C = HH(C, D, A, B, x[11], 16, 0x6d9d6122);
            B = HH(B, C, D, A, x[14], 23, 0xfde5380c);
            A = HH(A, B, C, D, x[1], 4 ,0xa4beea44);
            D = HH(D, A, B, C, x[4], 11,0x4bdecfa9);
            C = HH(C, D, A, B, x[7], 16, 0xf6bb4b60);
            B = HH(B, C, D, A, x[10], 23, 0xbebfbc70);
            A = HH(A, B, C, D, x[13], 4, 0x289b7ec6);
            D = HH(D, A, B, C, x[0], 11, 0xeaa127fa);
            C = HH(C, D, A, B, x[3], 16, 0xd4ef3085);
            B = HH(B, C, D, A, x[6], 23,  0x4881d05);
            A = HH(A, B, C, D, x[9], 4, 0xd9d4d039);
            D = HH(D, A, B, C, x[12], 11, 0xe6db99e5);
            C = HH(C, D, A, B, x[15], 16, 0x1fa27cf8);
            B = HH(B, C, D, A, x[2], 23, 0xc4ac5665);

//            Round 4.
//            Let [abcd k s t] denote the operation
//            a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s).
//            Do the following 16 operations.
            A = II(A, B, C, D, x[0], 6, 0xf4292244);
            D = II(D, A, B, C, x[7], 10, 0x432aff97);
            C = II(C, D, A, B, x[14], 15, 0xab9423a7);
            B = II(B, C, D, A, x[5], 21, 0xfc93a039);
            A = II(A, B, C, D, x[12], 6 ,0x655b59c3);
            D = II(D, A, B, C, x[3], 10,0x8f0ccc92);
            C = II(C, D, A, B, x[10], 15, 0xffeff47d);
            B = II(B, C, D, A, x[1], 21, 0x85845dd1);
            A = II(A, B, C, D, x[8], 6, 0x6fa87e4f);
            D = II(D, A, B, C, x[15], 10, 0xfe2ce6e0);
            C = II(C, D, A, B, x[6], 15, 0xa3014314);
            B = II(B, C, D, A, x[13], 21, 0x4e0811a1);
            A = II(A, B, C, D, x[4], 6, 0xf7537e82);
            D = II(D, A, B, C, x[11], 10, 0xbd3af235);
            C = II(C, D, A, B, x[2], 15, 0x2ad7d2bb);
            B = II(B, C, D, A, x[9], 21, 0xeb86d391);

//            Then perform the following additions. (That is increment each
//            of the four registers by the value it had before this block
//            was started.)
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
     * Copied from RFC 1321
     * Page 4
     * https://tools.ietf.org/html/rfc1321
     *
     */
    private int F(int x, int y, int z){
        return (((x) & (y)) | ((~x) & (z)));
    }

    /**
     * G(X,Y,Z) = XZ v Y not(Z)
     *
     * Copied from RFC 1321
     * Page 4
     * https://tools.ietf.org/html/rfc1321
     *
     */
    private int G(int x, int y, int z){
        return (((x) & (z)) | ((y) & (~z)));
    }

    /**
     * H(X,Y,Z) = X xor Y xor Z
     *
     * Copied from RFC 1321
     * Page 4
     * https://tools.ietf.org/html/rfc1321
     *
     */
    private int H(int x, int y, int z){
        return ((x) ^ (y) ^ (z));
    }

    /**
     * I(X,Y,Z) = Y xor (X v not(Z))
     *
     * Copied from RFC 1321
     * Page 4
     * https://tools.ietf.org/html/rfc1321
     *
     */
    private int I(int x, int y, int z){
        return ((y) ^ ((x) | (~z)));
    }

    /**
     * Round 1
     */
    private int FF(int a, int b, int c, int d, int x, int s, int t){
        a += F(b, c, d) + x + t;
        return b + rol(a, s);
    }

    /**
     * Round 2
     */
    private int GG(int a, int b, int c, int d, int x, int s, int t){
        a += G(b, c, d) + x + t;
        return b + rol(a, s);
    }

    /**
     * Round 3
     */
    private int HH(int a, int b, int c, int d, int x, int s, int t){
        a += H(b, c, d) + x + t;
        return b + rol(a, s);
    }

    /**
     * Round 4
     */
    private int II(int a, int b, int c, int d, int x, int s, int t){
        a += I(b, c, d) + x + t;
        return b + rol(a, s);
    }

    private int rol(int x, int y){
        return ((x)<<(y))|((x)>>>(32-y));
    }

    /**
     * The message digest produced as output is A, B, C, D. That is, we
     * begin with the low-order byte of A, and end with the high-order byte
     * of D.
     *
     * This completes the description of MD5. A reference implementation in
     * C is given in the appendix.
     *
     * Copied from RFC 1321
     * Page 6
     * https://tools.ietf.org/html/rfc1321
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
