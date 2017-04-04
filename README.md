# Encryption
Implementation of encription methods

## Download

Gradle:
```groovy
compile 'ru.bullyboo.ecryption:encoder:1.0.0'
```
Maven:
```xml
<dependency> 
  <groupId>ru.bullyboo.ecryption</groupId> 
  <artifactId>encoder</artifactId> 
  <version>1.0.0</version> 
  <type>pom</type> 
</dependency>
```
JAR:

[Download](https://github.com/BullyBoo/Encryption/releases/download/1.0.0/encoder-1.0.0.jar)

[Source](https://github.com/BullyBoo/Encryption/releases/download/1.0.0/encoder-1.0.0-sources.jar)

## Usage

The main class of this library is Encoder.
From this class you can get access for all enryption methods, via Builder pattern.
Every Builder has a basic methods - message, method, key.

For example:
``` java
String encrypt = Encoder.BuilderAES()
                    .message("test message")
                    .method(AES.Method.AES_CBC_PKCS5PADDING)
                    .key("test key")
                    .keySize(AES.Key.SIZE_128)
                    .iVector("test vector")
                    .encrypt();
```

Every Builder has a default settings. For example, `BuilderAES` has default `key = ""`, default `keySize = 128 bits`, and default `vector = ""`.
So it's can be called easier:
``` java
String encrypt = Encoder.BuilderAES()
                    .message("test message")
                    .method(AES.Method.AES_CBC_PKCS5PADDING)
                    .encrypt();
```

If you want to decrypt your message you can use `decrypt();` method in place of encrypt.

`encrypt();` and `decrypt();` method are synchronous.

For calling it asynchronous, you should call `.encrypeAsync();` or `decryptAsync();`.
Also you need add callback for getting result of encryption/decryption.
Example:
``` java
Encoder.BuilderAES()
                .method(AES.Method.AES_CBC_PKCS5PADDING)
                .message("test message")
                .key("test key")
                .encryptCallBack(new EncodeCallback() {
                    @Override
                    public void onSuccess(String result) {
                        //TODO somethink
                    }

                    @Override
                    public void onFailure(Throwable e) {
                        e.printStackTrace();
                    }
                }).encrypeAsync();
```

More information about supports methods, about keySizes and examples of using you can find [here](https://github.com/BullyBoo/Encryption/blob/master/Documentation.md)

## License
```
Copyright (C) 2017 BullyBoo

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  ```
