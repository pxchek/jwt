package com.app.jwt.config;

import org.apache.commons.codec.binary.Base64;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyProperties {
    public static RSAPublicKey readPublicKey() throws Exception {
        String publicKeyPEM = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApMi4QUipUmziNOvgfNzwDrBKmCJ/SmnyjuKkz4FKM1bE4bPG+UJ1hL/nHaB/ruITIie1B1ZuShzyCM7Q0Ju+v+eA7o1XPPXAToONQcbdrPxMGoX3fup5asVMSI5i4yI8OcLLQXybw3O+QbfP76AsyJWtBuurX/J8Don2YX0n6IYmMJvyWQ0keDQR4LaJi2DaIyR8le6vhJJGcYJroUiqeWqKwY3TzwU+6pUHrGlqqlTj/8sqpoaWO+fL3xdVK1b1MNriwIrNAQhd6XAMrr8u+tjoNNaJAhXyPdAxMyuxJxR2jTN9Kho3IH1aSHGGDvWd7KCEA6cU6Q0ZV6x+6JzxhwIDAQAB";

        byte[] encoded = Base64.decodeBase64(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
}
