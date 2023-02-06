package com.app.jwt.config;

import org.apache.commons.codec.binary.Base64;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyProperties {
    public static RSAPublicKey readPublicKey() throws Exception {
        String publicKeyPEM = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCAg0L1m7hMLqMygCvToNU7fWTSKjj6LvRcgRJe/oPF2P+NdjvSC0kCgUiXQwwR0ZQKxdWp21l2LGTbp6fLpDYCKzJSySLv4kkA2tsEZB+KYhNad/WKppWCEWq4Qq4CyGrP9bY7OiQxgVt225bI5SuEgRliYKHM+hC1niDgat0SpwIDAQAB"
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.decodeBase64(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
}
