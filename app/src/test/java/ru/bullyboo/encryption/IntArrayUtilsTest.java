package ru.bullyboo.encryption;

import org.junit.Test;

import ru.bullyboo.encoder.utils.IntArrayUtils;

/**
 * Created by BullyBoo on 17.07.2017.
 */

public class IntArrayUtilsTest {

    private int[] array = new int[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

    @Test
    public void circleShiftRight(){
        int[] ints = IntArrayUtils.circleShiftRight(array, 3);

        printArray(ints);
    }

    @Test
    public void circleShiftLeft(){
        int[] ints = IntArrayUtils.circleShiftLeft(array, 3);

        printArray(ints);
    }

    private void printArray(int[] array){

        for(int i = 0; i < array.length; i++){
            System.out.print(array[i] + ", ");
        }
    }
}
