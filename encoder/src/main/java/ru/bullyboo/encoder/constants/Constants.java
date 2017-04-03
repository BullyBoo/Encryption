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

package ru.bullyboo.encoder.constants;

/**
 * Constants what are using in this library
 */
public class Constants {

    /**
     * Exceptions messages
     */
    public static final String MESSAGE_EXCEPTION = "Message was not set";
    public static final String METHOD_EXCEPTION = "Method was not set";
    public static final String METHOD_CFB_OFB_EXCEPTION = "Wrong method number. Set the method number between 8 and 128";
    public static final String KEY_SIZE_EXCEPTION = "Key size can`t be equal to 0";
    public static final String LESS_ZERO_KEY_SIZE_EXCEPTION = "Key size can`t be less than 0";

    public static final String RSA_KEY_EXCEPTION = "Wrong key size value. Set the key size between 512 and 65536";
    public static final String RSA_KEY_MULTIPLY_EXCEPTION = "Wrong key size value. Key must be a multiple of 64";
    public static final String RSA_KEY_CALLBACK_EXCEPTION = "Key Callback was not set";
    public static final String RSA_HAS_NOT_KEY_EXCEPTION = "Private key was not set. Try to use privateKey() or key() methods";
    public static final String RSA_KEY_SIZE_EXCEPTION = "Key size was not set";

    public static final String PBE_KEY_SIZE_EXCEPTION = "Key size is not valid. Key size must be: ";

}
