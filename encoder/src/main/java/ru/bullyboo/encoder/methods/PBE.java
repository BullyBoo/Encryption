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

package ru.bullyboo.encoder.methods;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import ru.bullyboo.encoder.Base64;

/**
 * PBE Encrypt/Decrypt class
 */
public class PBE extends BaseMethod{

    private static final int VECTOR_LEGHT = 8;

    /**
     * All supported methods
     */
    public enum Method{

        PBE_with_SHA_1_and_DESede ("PBEWithSHA1AndDESede/CBC/PKCS5Padding", new int[]{16, 24}),
        PBE_with_MD5_and_AES_128_CBC_OPENSSL ("PBEWITHMD5AND128BITAES-CBC-OPENSSL", new int[]{16}),
        PBE_with_MD5_and_AES_192_CBC_OPENSSL ("PBEWITHMD5AND192BITAES-CBC-OPENSSL", new int[]{24}),
        PBE_with_MD5_and_AES_256_CBC_OPENSSL ("PBEWITHMD5AND256BITAES-CBC-OPENSSL", new int[]{32}),
        PBE_with_MD5_and_DES ("PBEWITHMD5ANDDES", new int[]{8}),
        PBE_with_MD5_and_RC2 ("PBEWITHMD5ANDRC2", new int[]{8}),
        PBE_with_SHA_1_and_AES_128_CBC_BC ("PBEWITHSHA1AND128BITAES-CBC-BC", new int[]{16}),
        PBE_with_SHA_1_and_RC2_128_CBC ("PBEWITHSHA1AND128BITRC2-CBC", new int[]{16}),
        PBE_with_SHA_1_and_RC4_128 ("PBEWITHSHA1AND128BITRC4", new int[]{16}),
        PBE_with_SHA_1_and_AES_192_CBC_BC ("PBEWITHSHA1AND192BITAES-CBC-BC", new int[]{24}),
        PBE_with_SHA_1_and_2_KEY_TRIPLE_DES_CBC ("PBEWITHSHA1AND2-KEYTRIPLEDES-CBC", new int[]{16, 24}),
        PBE_with_SHA_1_and_AES_256_CBC_BC ("PBEWITHSHA1AND256BITAES-CBC-BC", new int[]{32}),
        PBE_with_SHA_1_and_3_KEY_TRIPLE_DES_CBC ("PBEWITHSHA1AND3-KEYTRIPLEDES-CBC", new int[]{16, 24}),
        PBE_with_SHA_1_and_RC2_40_CBC ("PBEWITHSHA1AND40BITRC2-CBC", new int[]{8}),
        PBE_with_SHA_1_and_RC4_40 ("PBEWITHSHA1AND40BITRC4", new int[]{8}),
        PBE_with_SHA_1_and_DES ("PBEWITHSHA1ANDDES", new int[]{8}),
        PBE_with_SHA_1_and_DESEDE ("PBEWITHSHA1ANDDESEDE", new int[]{16, 32}),
        PBE_with_SHA_1_and_RC2 ("PBEWITHSHA1ANDRC2", new int[]{8}),
        PBE_with_SHA_256_and_AES_128_CBC_BC ("PBEWITHSHA256AND128BITAES-CBC-BC", new int[]{16}),
        PBE_with_SHA_256_and_AES_192_CBC_BC ("PBEWITHSHA256AND192BITAES-CBC-BC", new int[]{24}),
        PBE_with_SHA_256_and_AES_256_CBC_BC ("PBEWITHSHA256AND256BITAES-CBC-BC", new int[]{32}),
        PBE_with_SHA_and_AES_128_CBC_BC ("PBEWITHSHAAND128BITAES-CBC-BC", new int[]{16}),
        PBE_with_SHA_and_RC2_128_CBC ("PBEWITHSHAAND128BITRC2-CBC", new int[]{16}),
        PBE_with_SHA_and_RC4_128 ("PBEWITHSHAAND128BITRC4", new int[]{16}),
        PBE_with_SHA_and_AES_192_CBC_BC ("PBEWITHSHAAND192BITAES-CBC-BC", new int[]{24}),
        PBE_with_SHA_and_2_KEY_TRIPLE_DES_CBC ("PBEWITHSHAAND2-KEYTRIPLEDES-CBC", new int[]{16, 24}),
        PBE_with_SHA_and_AES_256_CBC_BC ("PBEWITHSHAAND256BITAES-CBC-BC", new int[]{32}),
        PBE_with_SHA_and_3_KEY_TRIPLE_DES_CBC ("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", new int[]{16, 24}),
        PBE_with_SHA_and_RC2_40_CBC ("PBEWITHSHAAND40BITRC2-CBC", new int[]{8}),
        PBE_with_SHA_and_RC4_40 ("PBEWITHSHAAND40BITRC4", new int[]{8}),
        PBE_with_SHA_and_TWOFISH_CBC ("PBEWITHSHAANDTWOFISH-CBC", new int[]{8}),
        PBE_with_SHA_and_3_KEY_TRIPLE_DES ("PBEWithSHAAnd3KeyTripleDES", new int[]{16, 24});

        private final String method;

        private final int[] keySizes;

        Method(String method, int[] keySizes) {
            this.method = method;
            this.keySizes = keySizes;
        }

        public String getMethod() {
            return method;
        }

        public int[] getKeySizes() {
            return keySizes;
        }
    }

    public static KeySize setKeySize(int keySize){
        return new KeySize(keySize);
    }

    /**
     * This class checks the key size
     */
    public static class KeySize{

        private final int size;

        KeySize(int size) {
            this.size = size;
        }

        public int getSize() {
            return size;
        }
    }

    /**
     * Implementation of PBE encryption
     */
    public static String encrypt(Method method, byte[] key, KeySize keySize, byte[] vector, byte[]  message) throws Exception{

//        generate Key
        byte[] keyBytes = generateKey(key, keySize.getSize());
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes , method.getMethod());

//        generate Initialization Vector
        byte[] keyBytesIv = generateVector(vector, VECTOR_LEGHT);
        IvParameterSpec ivSpec = new IvParameterSpec(keyBytesIv);

        Cipher cipher = Cipher.getInstance(method.getMethod());

        if(hasInitVector(method.getMethod())){
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        }

        byte[] cipherText = cipher.doFinal(message);

        return Base64.encodeToString(cipherText, Base64.DEFAULT);
    }

    /**
     * Implementation of PBE decryption
     */
    public static String decrypt(Method method, byte[] key, KeySize keySize, byte[] vector, byte[]  message) throws Exception {

//        generate Key
        byte[] keyBytes = generateKey(key, keySize.getSize());
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, method.getMethod());

//        generate Initialization Vector
        byte[] keyBytesIv = generateVector(vector, VECTOR_LEGHT);
        IvParameterSpec ivSpec = new IvParameterSpec(keyBytesIv);

        Cipher cipher = Cipher.getInstance(method.getMethod());

        if (hasInitVector(method.getMethod())) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        }

        byte[] cipherText = cipher.doFinal(Base64.decode(message, Base64.DEFAULT));

        return new String(cipherText);
    }
}
