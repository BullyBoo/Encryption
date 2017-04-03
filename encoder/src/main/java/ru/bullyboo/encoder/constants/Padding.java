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
 * All supported Padding
 */
public enum Padding {

    NO_PADDING ("NoPadding"),
    PKCS5PADDING("PKCS5Padding"),
    PKCS7PADDING("PKCS7Padding"),
    ISO10126PADDING("ISO10126Padding");


    private final String padding;

    Padding(String padding) {
        this.padding = padding;
    }

    public String getPadding() {
        return padding;
    }
}
