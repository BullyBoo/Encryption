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

package ru.bullyboo.encoder.utils;

/**
 * Class helper for working with arrays
 */

public class ArrayUtils {

    public static int[] mergeArrays(byte[] mainArray, int[] appendArray){

        int[] array = new int[mainArray.length + appendArray.length];

        int mainSize = mainArray.length;
        int appendSize = appendArray.length;

        for(int i = 0; i < mainSize; i++){
            array[i] = mainArray[i];
        }

        System.arraycopy(appendArray, 0, array, mainSize, appendSize);

        return array;
    }

    public static int[] mergeArrays(int[] mainArray, int[] appendArray){
        int[] array = new int[mainArray.length + appendArray.length];

        int mainSize = mainArray.length;
        int appendSize = appendArray.length;

        System.arraycopy(mainArray, 0, array, 0, mainSize);

        System.arraycopy(appendArray, 0, array, mainSize, appendSize);

        return array;
    }

}
