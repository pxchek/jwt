package com.app.jwt.config;

import org.apache.commons.codec.binary.Base64;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class PrivateKeyProperties {
    public static RSAPrivateKey readPrivateKey() throws Exception {
        String privateKeyPEM = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAICDQvWbuEwuozKAK9Og1Tt9ZNIqOPou9FyBEl7+g8XY/412O9ILSQKBSJdDDBHRlArF1anbWXYsZNunp8ukNgIrMlLJIu/iSQDa2wRkH4piE1p39YqmlYIRarhCrgLIas/1tjs6JDGBW3bblsjlK4SBGWJgocz6ELWeIOBq3RKnAgMBAAECgYADw9SyXV2I3dTqJdci3BNjKslJXvNMYRPHogBnyA0UPsc93bji7nG1IRR/WfeAjiNILYOU9lgoniRWSxMfZDAw1WmQ0JfVkk6n7Zog8KWSbH9zlYtlFn/1kUYE+suOtvcMR1Bk+J3LNz7+L3bIW84ikqiG+MNk60mbKXtA/DMsAQJBAMSdbU8+4fiqWw1/qH7UeBFp+wOImLmqMTiqFBri2e39/JDyAxIls8+wQko4Q2iZJ3hSHlqr4c7I/sXwLuxAuGUCQQCnVBDr8AhLMHuianyXn/7Wz8MOKWTfcj17eWhQQVu3hf5HV+onoB0FpBTGCkdGX2Ex9wxicfYC8YVdvBkIuSAbAkBg4YWsR7sHUcIeC6pWHJGxWvyCCDvhOLiaSEwx11g1SjK6pVXYClXo39w6QDEPCHCHfEdSvGE/CJFprWkhpt51AkAgvKvK3V1iCIxHzHmv2JetQ1ywKp0Xsmwg+jHUcdUV5NtI7gRb2FGVRvLhhCVJuWN0uRbtM8qj7Mjg++oR8NY9AkBCVMweeDeptIVetRrPwy0Uk8sNt2/lEvWQaU2PiSJ4MSDG5qvp6/UnPV3sUEVd6rb7ls9qsX9WZbvDTxB/s6yt"
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.decodeBase64(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

}
