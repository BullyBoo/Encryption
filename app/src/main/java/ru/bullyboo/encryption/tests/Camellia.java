package ru.bullyboo.encryption.tests;

import java.nio.IntBuffer;
import java.nio.LongBuffer;

import ru.bullyboo.encoder.utils.ArrayUtils;
import ru.bullyboo.encoder.utils.IntArrayUtils;

/**
 * Created by BullyBoo on 17.07.2017.
 */

public class Camellia {

    private static final int[] SBOX1 = new int[]{
            112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65,
            35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189,
            134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26,
            166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77,
            139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153,
            223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215,
            20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34,
            254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80,
            170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210,
            16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148,
            135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226,
            82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46,
            233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89,
            120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250,
            114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164,
            64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158
    };

    private static int[] SBOX2;
    private static int[] SBOX3;
    private static int[] SBOX4;

    private static final int[] C1 = new int[] {0xA0, 0x9E, 0x66, 0x7F, 0x3B, 0xCC, 0x90, 0x8B};
    private static final int[] C2 = new int[] {0xB6, 0x7A, 0xE8, 0x58, 0x4C, 0xAA, 0x73, 0xB2};
    private static final int[] C3 = new int[] {0xC6, 0xEF, 0x37, 0x2F, 0xE9, 0x4F, 0x82, 0xBE};
    private static final int[] C4 = new int[] {0x54, 0xFF, 0x53, 0xA5, 0xF1, 0xD3, 0x6F, 0x1C};
    private static final int[] C5 = new int[] {0x10, 0xE5, 0x27, 0xFA, 0xDE, 0x68, 0x2D, 0x1D};
    private static final int[] C6 = new int[] {0xB0, 0x56, 0x88, 0xC2, 0xB3, 0xE6, 0xC1, 0xFD};

    private static final int[] MASK8 = new int[]{0xff};
    private static final int[] MASK32 = new int[]{0xff, 0xff, 0xff, 0xff};
    private static final int[] MASK64 = new int[]{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    private static final int[] MASK128 = new int[]{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    private int[] message;

    private int[] key;

    private int[] KL;
    private int[] KR;

    private int[] KA;
    private int[] KB;

    private int[] D1;
    private int[] D2;

    public Camellia() {
        int size = SBOX1.length;

        SBOX2 = new int[size];
        SBOX3 = new int[size];
        SBOX4 = new int[size];

        SBOX2 = IntArrayUtils.circleShiftLeft(SBOX1, 1);
        SBOX3 = IntArrayUtils.circleShiftLeft(SBOX1, 7);

        for(int i = 0; i < size; i++){
            SBOX4[i] = SBOX1[i << 1];
        }
    }

    public enum KeySize{
        SIZE_128(16),
        SIZE_192(24),
        SIZE_256(32);

        private int byteCounts;

        KeySize(int byteCounts) {
            this.byteCounts = byteCounts;
        }

        public int getByteCounts() {
            return byteCounts;
        }
    }

    public byte[] encrypt(byte[] message, byte[] key, KeySize keySize){

        this.key = appendKeyPadding(key);

        initKL(this.key);
        initKR(this.key);

        countKA_KB();

        countKeys();

        int i = (int) 0e0f;

        return null;
    }

    private int[] appendKeyPadding(byte[] byteKey){
        int[] intKey = ArrayUtils.convertByteArrayToIntArray(byteKey);

        key = new int[32];

        if(intKey.length >= 32){
            System.arraycopy(intKey, 0, key, 0, 32);
        } else {
            System.arraycopy(intKey, 0, key, 0, intKey.length);

            for(int i = intKey.length; i < 32; i++){
                key[i] = 0;
            }
        }
        return key;
    }

    private void initKL(int[] key){
        KL = new int[16];

        System.arraycopy(key, 0, KL, 0, 16);
    }

    private void initKR(int[] key){
        KR = new int[16];

        System.arraycopy(key, 16, KR, 0, 16);
    }

    private void countKA_KB(){
//        D1 = (KL ^ KR) >> 64;
        D1 = IntArrayUtils.xor(KL, KR);
        D1 = IntArrayUtils.shiftRight(D1, 64);

//        D2 = (KL ^ KR) & MASK64;
        D2 = IntArrayUtils.xor(KL, KR);
        D2 = IntArrayUtils.and(D1, MASK64);

//        D2 = D2 ^ F(D1, C1);
        D2 = IntArrayUtils.xor(D2, F(D1, C1));

//        D1 = D1 ^ F(D2, C2);
        D1 = IntArrayUtils.xor(D1, F(D2, C2));

//        D1 = D1 ^ (KL >> 64);
        D1 = IntArrayUtils.xor(D1, IntArrayUtils.shiftRight(KL, 64));

//        D2 = D2 ^ (KL & MASK64);
        D2 = IntArrayUtils.xor(D2, IntArrayUtils.and(KL, MASK64));

//        D2 = D2 ^ F(D1, C3);
        D2 = IntArrayUtils.xor(D2, F(D1, C3));

//        D1 = D1 ^ F(D2, C4);
        D1 = IntArrayUtils.xor(D1, F(D2, C4));

//        KA = (D1 << 64) | D2;
        KA = IntArrayUtils.or(IntArrayUtils.shiftLeft(D1, 64), D2);

//        D1 = (KA ^ KR) >> 64;
        D1 = IntArrayUtils.shiftLeft(IntArrayUtils.xor(KA, KR), 64);

//        D2 = (KA ^ KR) & MASK64;
        D2 = IntArrayUtils.and(IntArrayUtils.xor(KA, KR), MASK64);

//        D2 = D2 ^ F(D1, C5);
        D2 = IntArrayUtils.xor(D2, F(D1, C5));

//        D1 = D1 ^ F(D2, C6);
        D1 = IntArrayUtils.xor(D1, F(D2, C6));

//        KB = (D1 << 64) | D2;
        KB = IntArrayUtils.or(IntArrayUtils.shiftLeft(D1, 64), D2);

    }

    private int[] kw1, kw2, kw3, kw4;
    private int[] k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16, k17, k18;
    private int[] ke1, ke2, ke3, ke4;

    private void countKeys(){
//        kw1 = (KL <<<   0) >> 64;
        kw1 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KL, 0), 64);

//        kw2 = (KL <<<   0) & MASK64;
        kw2 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KL, 0), MASK64);

//        k1  = (KA <<<   0) >> 64;
        k1 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KA, 0), 64);

//        k2  = (KA <<<   0) & MASK64;
        k2 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KA, 0), MASK64);

//        k3  = (KL <<<  15) >> 64;
        k3 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KL, 15), 64);

//        k4  = (KL <<<  15) & MASK64;
        k4 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KL, 15), MASK64);

//        k5  = (KA <<<  15) >> 64;
        k5 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KA, 15), 64);

//        k6  = (KA <<<  15) & MASK64;
        k6 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KA, 15), MASK64);

//        ke1 = (KA <<<  30) >> 64;
        ke1 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KA, 30), 64);

//        ke2 = (KA <<<  30) & MASK64;
        ke2 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KA, 30), MASK64);

//        k7  = (KL <<<  45) >> 64;
        k7 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KL, 45), 64);

//        k8  = (KL <<<  45) & MASK64;
        k8 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KL, 45), MASK64);

//        k9  = (KA <<<  45) >> 64;
        k9 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KA, 45), 64);

//        k10 = (KL <<<  60) & MASK64;
        k10 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KL, 60), MASK64);

//        k11 = (KA <<<  60) >> 64;
        k11 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KA, 60), 64);

//        k12 = (KA <<<  60) & MASK64;
        kw2 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KA, 60), MASK64);

//        ke3 = (KL <<<  77) >> 64;
        ke3 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KL, 77), 64);

//        ke4 = (KL <<<  77) & MASK64;
        ke4 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KL, 77), MASK64);

//        k13 = (KL <<<  94) >> 64;
        k13 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KL, 94), 64);

//        k14 = (KL <<<  94) & MASK64;
        k14 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KL, 94), MASK64);

//        k15 = (KA <<<  94) >> 64;
        k15 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KA, 94), 64);

//        k16 = (KA <<<  94) & MASK64;
        k16 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KA, 94), MASK64);

//        k17 = (KL <<< 111) >> 64;
        k17 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KL, 111), 64);

//        k18 = (KL <<< 111) & MASK64;
        k18 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KL, 111), MASK64);

//        kw3 = (KA <<< 111) >> 64;
        kw3 = IntArrayUtils.shiftLeft(IntArrayUtils.circleShiftLeft(KA, 111), 64);

//        kw4 = (KA <<< 111) & MASK64;
        kw4 = IntArrayUtils.and(IntArrayUtils.circleShiftLeft(KA, 111), MASK64);

    }

    private int[] F(int[] F_IN, int[] KE){
//        x  = F_IN ^ KE;
        int[] x = IntArrayUtils.xor(F_IN, KE);

//        t1 =  x >> 56;
        int[] t1 = IntArrayUtils.shiftRight(x, 56);
        t1 = IntArrayUtils.and(t1, MASK8);

//        t2 = (x >> 48) & MASK8;
        int[] t2 = IntArrayUtils.shiftRight(x, 48);
        t2 = IntArrayUtils.and(t2, MASK8);

//        t3 = (x >> 40) & MASK8;
        int[] t3 = IntArrayUtils.shiftRight(x, 40);
        t3 = IntArrayUtils.and(t3, MASK8);

//        t4 = (x >> 32) & MASK8;
        int[] t4 = IntArrayUtils.shiftRight(x, 32);
        t4 = IntArrayUtils.and(t4, MASK8);

//        t5 = (x >> 24) & MASK8;
        int[] t5 = IntArrayUtils.shiftRight(x, 24);
        t5 = IntArrayUtils.and(t5, MASK8);

//        t6 = (x >> 16) & MASK8;
        int[] t6 = IntArrayUtils.shiftRight(x, 16);
        t6 = IntArrayUtils.and(t6, MASK8);

//        t7 = (x >>  8) & MASK8;
        int[] t7 = IntArrayUtils.shiftRight(x, 8);
        t7 = IntArrayUtils.and(t7, MASK8);

//        t8 =  x & MASK8;
        int[] t8 = IntArrayUtils.and(x, MASK8);

//        t1 = SBOX1[t1];
        long T1 = SBOX1[IntArrayUtils.toInt(t1)];

//        t2 = SBOX2[t2];
        long T2 = SBOX2[IntArrayUtils.toInt(t2)];

//        t3 = SBOX3[t3];
        long T3 = SBOX3[IntArrayUtils.toInt(t3)];

//        t4 = SBOX4[t4];
        long T4 = SBOX4[IntArrayUtils.toInt(t4)];

//        t5 = SBOX2[t5];
        long T5 = SBOX2[IntArrayUtils.toInt(t5)];

//        t6 = SBOX3[t6];
        long T6 = SBOX3[IntArrayUtils.toInt(t6)];

//        t7 = SBOX4[t7];
        long T7 = SBOX4[IntArrayUtils.toInt(t7)];

//        t8 = SBOX1[t8];
        long T8 = SBOX2[IntArrayUtils.toInt(t8)];

//        y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
        long y1 = T1 ^ T3 ^ T4 ^ T6 ^ T7 ^ T8;

//        y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
        long y2 = T1 ^ T2 ^ T4 ^ T5 ^ T7 ^ T8;

//        y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
        long y3 = T1 ^ T2 ^ T3 ^ T5 ^ T6 ^ T8;

//        y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
        long y4 = T2 ^ T3 ^ T4 ^ T5 ^ T6 ^ T7;

//        y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
        long y5 = T1 ^ T2 ^ T6 ^ T7 ^ T8;

//        y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
        long y6 = T2 ^ T3 ^ T5 ^ T7 ^ T8;

//        y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
        long y7 = T3 ^ T4 ^ T5 ^ T6 ^ T8;

//        y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
        long y8 = T1 ^ T4 ^ T5 ^ T6 ^ T7;

//        F_OUT = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32)| (y5 << 24) | (y6 << 16) | (y7 <<  8) | y8;
        long F_OUT = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32)| (y5 << 24) | (y6 << 16) | (y7 <<  8) | y8;

        return IntArrayUtils.toArray(F_OUT);

    }
}
