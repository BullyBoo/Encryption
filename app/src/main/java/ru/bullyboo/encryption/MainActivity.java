package ru.bullyboo.encryption;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;

import ru.bullyboo.encryption.tests.TestAES;
import ru.bullyboo.encryption.tests.TestARCFOUR;
import ru.bullyboo.encryption.tests.TestBlowfish;
import ru.bullyboo.encryption.tests.TestDES;
import ru.bullyboo.encryption.tests.TestDESede;
import ru.bullyboo.encryption.tests.TestHMAC;
import ru.bullyboo.encryption.tests.TestHash;
import ru.bullyboo.encryption.tests.TestPBE;
import ru.bullyboo.encryption.tests.TestRSA;

public class MainActivity extends AppCompatActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        TestAES.testAllAES_Methods();
//        TestAES.testCBF_AESMethods();
//        TestAES.testOBF_AESMethods();
//        TestAES.testAES_Async();

//        TestARCFOUR.testAll_ARCFOUR();
//        TestARCFOUR.test_ARCFOUR();
//        TestARCFOUR.testARCFOUR_Async();

//        TestRSA.testAllRSA_Methods(2048);
//        TestRSA.generateKey();
//        TestRSA.testRSA_Async();
//        TestRSA.testRSA_Async_generateKey();

//        TestHMAC.testHMAC();
//        TestHMAC.testHMAC_Async();

//        TestPBE.testAll_PBE();
//        TestPBE.testPBE_Async();

//        TestDES.testAll_DES();
//        TestDES.testAll_CFB_DES();
//        TestDES.testAll_OFB_DES();
//        TestDES.testDES_Async();

//        TestDESede.testAll_DESede();
//        TestDESede.testDESede_Async();

//        TestBlowfish.testAll_Blowfish();
//        TestBlowfish.testAll_CFB_Blowfish();
//        TestBlowfish.testAll_OFB_Blowfish();
//        TestBlowfish.testBlowfish_Async();

//        TestHash.testHash();
    }
}
