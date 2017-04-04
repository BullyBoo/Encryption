

## Builders

|Method|Builder|
|-------|-------|
|AES|BuilderAES|
|ARCFOUR|BuilderARCFOUR|
|Blowfish|BuilderBlowfish|
|DES|BuilderDES|
|DESede|BuilderDESede|
|RSA|BuilderRSA|
|HMAC|BuilderHMAC|
|PBE|BuilderPBE|

## Default values
### AES
```java 
byte[] key = new byte[]{};
AES.Key keySize = AES.Key.SIZE_128;
byte[] iVector = new byte[]{};
```
### ARCFOUR
```java 
byte[] key = new byte[]{};
int keySize = 1;
```
### Blowfish
```java
byte[] key = new byte[]{};
int keySize = 1;
byte[] iVector = new byte[]{};
```
### DES
```java
byte[] key = new byte[]{};
int keySize = 1;
```
### DESede
```java
byte[] key = new byte[]{};
DESede.Key keySize = DESede.Key.SIZE_128;
byte[] iVector = new byte[]{};
```
### HMAC
```java
byte[] key = new byte[]{};
```
### PBE
```java
byte[] key = new byte[]{};
PBE.KeySize keySize;
byte[] vector = new byte[]{};
```
### RSA
```java
RSA.KeySize keySize = RSA.setKeySize(512);
RSA.KeyCallback keyCallback;
```

## Examples
### AES
Synchronous:
```java 
String encrypt = Encoder.BuilderAES()
                    .method(AES.Method.AES_CBC_PKCS5PADDING)
                    .message("test message")
                    .key("test key") // not necessary
                    .keySize(AES.Key.SIZE_128) // not necessary
                    .iVector("test vector") // not necessary
                    .encrypt();
```
Asynchronous:
```java 
Encoder.BuilderAES()
                .method(AES.Method.AES_CBC_PKCS5PADDING)
                .message("test message")
                .key("test key") // not necessary
                .keySize(AES.Key.SIZE_128) // not necessary
                .iVector("test vector") // not necessary
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encrypeAsync();
```
### ARCFOUR
Synchronous:
```java 
String encrypt = Encoder.BuilderARCFOUR()
                .message("test message")
                .key("test key") // not necessary
                .keySize(1024) // not necessary
                .encrypt();
```
Asynchronous:
```java 
Encoder.BuilderARCFOUR()
                .message("test message")
                .key("test key") // not necessary
                .keySize(1024) // not necessary
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encrypeAsync();
```
### Blowfish
Synchronous:
```java 
String encrypt = Encoder.BuilderBlowfish()
                .message("test message")
                .method(Blowfish.Method.BLOWFISH_CBC_ISO10126Padding)
                .key(key) // not necessary
                .keySize(1024) // not necessary
                .iVector("test vector") // not necessary
                .encrypt();
```
Asynchronous:
```java 
Encoder.BuilderBlowfish()
                .method(Blowfish.Method.BLOWFISH_CBC_ISO10126Padding)
                .message("test message")
                .key("test key") // not necessary
                .keySize(1024) // not necessary
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encrypeAsync();
```
### DES
Synchronous:
```java 
String encrypt = Encoder.BuilderDES()
                .message("test message")
                .method(DES.Method.DES_CBC_ISO10126Padding)
                .key("test key") // not necessary   
                .iVector("test vector") // not necessary
                .encrypt();
```
Asynchronous:
```java 
Encoder.BuilderDES()
                .method(DES.Method.DES_CBC_ISO10126Padding)
                .message("test message")
                .key("test key") // not necessary
                .iVector("test vector") // not necessary
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encrypeAsync();
```
### DESede
Synchronous:
```java 
String encrypt = Encoder.BuilderDESede()
                        .method(DESede.Method.DESEDE_CBC_ISO10126Padding)
                        .message("test message")
                        .key("test key") // not necessary
                        .keySize(DESede.Key.SIZE_128) // not necessary
                        .iVector("test vector") // not necessary
                        .encrypt();
```
Asynchronous:
```java 
Encoder.BuilderDESede()
                .method(DESede.Method.DESEDE_CBC_ISO10126Padding)
                .message("test message")
                .key("test key") // not necessary
                .keySize(DESede.Key.SIZE_128) // not necessary
                .iVector("test vector") // not necessary
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encrypeAsync();
```
### HMAC
Synchronous:
```java 
String encrypt = Encoder.BuilderHMAC()
                    .message("test message")
                    .method(HMAC.Method.HMAC_SHA_1)
                    .key("test key") // not necessary
                    .encrypt();
```
Asynchronous:
```java 
Encoder.BuilderHMAC()
                .method(HMAC.Method.HMAC_SHA_1)
                .message("test message")
                .key("test key") // not necessary
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encrypeAsync();
```
### PBE
Synchronous:
```java 
String encrypt = Encoder.BuilderPBE()
                    .message("test message")
                    .method(PBE.Method.PBE_with_MD5_and_AES_128_CBC_OPENSSL)
                    .key("test key") // not necessary
                    .keySize(PBE.setKeySize(16)) // not necessary
                    .iVector("test vector") // not necessary
                    .encrypt();
```
Asynchronous:
```java 
Encoder.BuilderPBE()
                .message("test message")
                .method(PBE.Method.PBE_with_MD5_and_AES_128_CBC_OPENSSL)
                .key("test key") // not necessary
                .keySize(PBE.setKeySize(16)) // not necessary
                .iVector("test vector") // not necessary
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encrypeAsync();
```
### RSA
Synchronous:
```java 
String encrypt = Encoder.BuilderRSA()
                        .message("test message")
                        .method(RSA.Method.RSA_ECB_OAEP_with_SHA1_and_MGF1_PADDING)
                        .key(keyPair) // or privateKey(); or publicKey()
                        .keySize(RSA.setKeySize(2048))
                        .encrypt();
```
Asynchronous:
```java 
Encoder.BuilderRSA()
                .message("test message")
                .method(RSA.Method.RSA_ECB_OAEP_with_SHA1_and_MGF1_PADDING)
                .key(keyPair) // or privateKey(); or publicKey()
                .keySize(RSA.setKeySize(2048))
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                })
                .encrypeAsync();
```

Also you can to generate a key for RSA:
```java 
KeyPair key = Encoder.BuilderRSA()
                .keySize(RSA.setKeySize(4096))
                .generateKey();
```
Asynchronous:
```java 
Encoder.BuilderRSA()
                .keySize(RSA.setKeySize(4096))
                .keyCallBack(new RSA.KeyCallback() {
                    @Override
                    public void onSuccess(KeyPair result) {
                        // TODO something
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                })
                .generateKeyAsync();
```
## Key sizes
### AES
```java 
AES.Key.SIZE_128
AES.Key.SIZE_192
AES.Key.SIZE_256
```
### ARCFOUR
```java 
1 <= key < ∞
```
### Blowfish
```java 
1 <= key < ∞
```
### DES
```java 
key size always equal 8
```
### DESede
```java
DES.Key.SIZE_128
DES.Key.SIZE_192
```
### HMAC
```java
key size equal length of byte array
```
### PBE
|Method|Size|
|-------|-------|
|PBEWithSHA1AndDESede/CBC/PKCS5Padding|16, 24|
|PBEWITHMD5AND128BITAES-CBC-OPENSSL|16|
|PBEWITHMD5AND192BITAES-CBC-OPENSSL|24|
|PBEWITHMD5AND256BITAES-CBC-OPENSSL|32|
|PBEWITHMD5ANDDES|8|
|PBEWITHMD5ANDRC2|8|
|PBEWITHSHA1AND128BITAES-CBC-BC|16|
|PBEWITHSHA1AND128BITRC2-CBC|16|
|PBEWITHSHA1AND128BITRC4|16|
|PBEWITHSHA1AND192BITAES-CBC-BC|24|
|PBEWITHSHA1AND2-KEYTRIPLEDES-CBC|16, 24|
|PBEWITHSHA1AND256BITAES-CBC-BC|32|
|PBEWITHSHA1AND3-KEYTRIPLEDES-CBC|16, 24|
|PBEWITHSHA1AND40BITRC2-CBC|8|
|PBEWITHSHA1AND40BITRC4|8|
|PBEWITHSHA1ANDDES|8|
|PBEWITHSHA1ANDDESEDE|16, 32|
|PBEWITHSHA1ANDRC2|8|
|PBEWITHSHA256AND128BITAES-CBC-BC|16|
|PBEWITHSHA256AND192BITAES-CBC-BC|24|
|PBEWITHSHA256AND256BITAES-CBC-BC|32|
|PBEWITHSHAAND128BITAES-CBC-BC|16|
|PBEWITHSHAAND128BITRC2-CBC|16|
|PBEWITHSHAAND128BITRC4|16|
|PBEWITHSHAAND192BITAES-CBC-BC|24|
|PBEWITHSHAAND2-KEYTRIPLEDES-CBC|16, 24|
|PBEWITHSHAAND256BITAES-CBC-BC|32|
|PBEWITHSHAAND3-KEYTRIPLEDES-CBC|16, 24|
|PBEWITHSHAAND40BITRC2-CBC|8|
|PBEWITHSHAAND40BITRC4|8|
|PBEWITHSHAANDTWOFISH-CBC|8|
|PBEWithSHAAnd3KeyTripleDES|16, 24|

If you will not set the keySize, encryption method will use the first value.

### RSA
```java
512 <= key < 65536
key must be muliple of 64
```
## All Supports encryption methods

|AES|ARCFOUR|Blowfish|
|-------|-------|-------|
|AES|	ARCFOUR|	Blowfish/ECB/NoPadding|
|AES/CBC/NoPadding|	|	Blowfish/ECB/PKCS5Padding|
|AES/CBC/PKCS5Padding|	|	Blowfish/ECB/PKCS7Padding|
|AES/CBC/PKCS7Padding|	|	Blowfish/ECB/ISO10126Padding|
|AES/CBC/ISO10126Padding|	|	Blowfish/CBC/NoPadding|
|AES/CTR/NoPadding|	|	Blowfish/CBC/PKCS5Padding|
|AES/CTR/PKCS5Padding|	|	Blowfish/CBC/PKCS7Padding|
|AES/CTR/PKCS7Padding|	|	Blowfish/CBC/ISO10126Padding|
|AES/CTR/ISO10126Padding|	|	Blowfish/CTR/NoPadding|
|AES/CFB/NoPadding|	|	Blowfish/CTR/PKCS5Padding|
|AES/CFB/PKCS5Padding|	|	Blowfish/CTR/PKCS7Padding|
|AES/CFB/PKCS7Padding|	|	Blowfish/CTR/ISO10126Padding|
|AES/CFB/ISO10126Padding|	|	Blowfish/CTS/NoPadding|
|AES/ECB/NoPadding|	|	Blowfish/CTS/PKCS5Padding|
|AES/ECB/PKCS5Padding|	|	Blowfish/CTS/PKCS7Padding|
|AES/ECB/PKCS7Padding|	|	Blowfish/CTS/ISO10126Padding|
|AES/ECB/ISO10126Padding|	|	Blowfish/CFB/NoPadding|
|AES/GCM/NoPadding|	|	Blowfish/CFB/PKCS5Padding|
|AES/OFB/NoPadding|	|	Blowfish/CFB/PKCS7Padding|
|AES/OFB/PKCS5Padding|	|	Blowfish/CFB/ISO10126Padding|
|AES/OFB/PKCS7Padding|	|	Blowfish/OFB/NoPadding|
|AES/OFB/ISO10126Padding|	|	Blowfish/OFB/PKCS5Padding|
||	|	Blowfish/OFB/PKCS7Padding|
||	|	Blowfish/OFB/ISO10126Padding|


|DES|DESede|HMAC|
|-------|-------|-------|
|DES/ECB/NoPadding|	DESEDE|	HMAC-MD5|
|DES/ECB/PKCS5Padding|	DESEDE/CBC/NoPadding|	HMAC-SHA1|
|DES/ECB/PKCS7Padding|	DESEDE/CBC/PKCS5Padding|	HMAC-SHA224|
|DES/ECB/ISO10126Padding|	DESEDE/CBC/PKCS7Padding|	HMAC-SHA256|
|DES/CBC/NoPadding|	DESEDE/CBC/ISO10126Padding|	HMAC-SHA384|
|DES/CBC/PKCS5Padding|	|	HMAC-SHA512|
|DES/CBC/PKCS7Padding|	|	|
|DES/CBC/ISO10126Padding|	|	|
|DES/CTR/NoPadding|	|	|
|DES/CTR/PKCS5Padding|	|	|
|DES/CTR/PKCS7Padding|	|	|
|DES/CTR/ISO10126Padding|	|	|
|DES/CTS/NoPadding|	|	|
|DES/CTS/PKCS5Padding|	|	|
|DES/CTS/PKCS7Padding|	|	|
|DES/CTS/ISO10126Padding|	|	|
|DES/CFB/NoPadding|	|	|
|DES/CFB/PKCS5Padding|	|	|
|DES/CFB/PKCS7Padding|	|	|
|DES/CFB/ISO10126Padding|	|	|
|DES/OFB/NoPadding|	|	|
|DES/OFB/PKCS5Padding|	|	|
|DES/OFB/PKCS7Padding|	|	|
|DES/OFB/ISO10126Padding|	|	|


|PBE|RSA|
|-------|-------|
|PBEWithSHA1AndDESede/CBC/PKCS5Padding|	RSA|
|PBEWITHMD5AND128BITAES-CBC-OPENSSL|	RSA/ECB/NoPadding|
|PBEWITHMD5AND192BITAES-CBC-OPENSSL|	RSA/ECB/PKCS1Padding|
|PBEWITHMD5AND256BITAES-CBC-OPENSSL|	RSA/ECB/OAEPPadding|
|PBEWITHMD5ANDDES|	RSA/ECB/PKCS1Padding|
|PBEWITHMD5ANDRC2|	RSA/None/NoPadding|
|PBEWITHSHA1AND128BITAES-CBC-BC|	RSA/ECB/OAEPWithMD5AndMGF1Padding|
|PBEWITHSHA1AND128BITRC2-CBC|	RSA/ECB/OAEPWithSHA1AndMGF1Padding|
|PBEWITHSHA1AND128BITRC4|	RSA/ECB/OAEPWithSHA-1AndMGF1Padding|
|PBEWITHSHA1AND192BITAES-CBC-BC|	RSA/ECB/OAEPWithSHA-224AndMGF1Padding|
|PBEWITHSHA1AND2-KEYTRIPLEDES-CBC|	RSA/ECB/OAEPWithSHA-256AndMGF1Padding|
|PBEWITHSHA1AND256BITAES-CBC-BC|	RSA/ECB/OAEPWithSHA-384AndMGF1Padding|
|PBEWITHSHA1AND3-KEYTRIPLEDES-CBC|	RSA/ECB/OAEPWithSHA-512AndMGF1Padding|
|PBEWITHSHA1AND40BITRC2-CBC|	|
|PBEWITHSHA1AND40BITRC4|	|
|PBEWITHSHA1ANDDES|	|
|PBEWITHSHA1ANDDESEDE|	|
|PBEWITHSHA1ANDRC2|	|
|PBEWITHSHA256AND128BITAES-CBC-BC|	|
|PBEWITHSHA256AND192BITAES-CBC-BC|	|
|PBEWITHSHA256AND256BITAES-CBC-BC|	|
|PBEWITHSHAAND128BITAES-CBC-BC|	|
|PBEWITHSHAAND128BITRC2-CBC|	|
|PBEWITHSHAAND128BITRC4|	|
|PBEWITHSHAAND192BITAES-CBC-BC|	|
|PBEWITHSHAAND2-KEYTRIPLEDES-CBC|	|
|PBEWITHSHAAND256BITAES-CBC-BC|	|
|PBEWITHSHAAND3-KEYTRIPLEDES-CBC|	|
|PBEWITHSHAAND40BITRC2-CBC|	|
|PBEWITHSHAAND40BITRC4|	|
|PBEWITHSHAANDTWOFISH-CBC|	|
|PBEWithSHAAnd3KeyTripleDES|	|
