package com.app.jwt.config;

import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class PrivateKeyProperties {
    public static RSAPrivateKey readPrivateKey(File file) {
        try {
            String key = new String(Files.readAllBytes(file.toPath()));

            byte[] encoded = Base64.decode(key);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            keyFact
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
            return privKey;
        } catch (Exception e) {

        }
        return null;
    }
}
