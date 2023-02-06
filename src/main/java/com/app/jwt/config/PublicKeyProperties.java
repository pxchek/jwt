package com.app.jwt.config;

import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyProperties {

    public static RSAPublicKey readPublicKey(File file) throws Exception {

        String publicKeyPEM = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDcTCCAlmgAwIBAgIIE6ZKGVzUUREwDQYJKoZIhvcNAQELBQAwZzELMAkGA1UE\n" +
                "BhMCVVMxCzAJBgNVBAgTAklMMRMwEQYDVQQHEwpOYXBlcnZpbGxlMQ8wDQYDVQQK\n" +
                "EwZhbWF6b24xEjAQBgNVBAsTCWVjb21tZXJjZTERMA8GA1UEAxMIUGFuaW5kcmEw\n" +
                "HhcNMjMwMjA2MDA0MDU3WhcNMjMwNTA3MDA0MDU3WjBnMQswCQYDVQQGEwJVUzEL\n" +
                "MAkGA1UECBMCSUwxEzARBgNVBAcTCk5hcGVydmlsbGUxDzANBgNVBAoTBmFtYXpv\n" +
                "bjESMBAGA1UECxMJZWNvbW1lcmNlMREwDwYDVQQDEwhQYW5pbmRyYTCCASIwDQYJ\n" +
                "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKu244sazYFX94xfZzwnCd07HWycx9t8\n" +
                "AOnSUy4SLH2JMKPGtuc2t+L5hjr+4WCSi3fsDlAeY9FPvXfm5SH7NfW23RFw6fXh\n" +
                "h8nwcC3uonQIzUuFczbdLWjBpncfLkAmSvjJ7IWwqyE3RJCtJrkgfZTlmwDqpNP9\n" +
                "7aZ3h3yhi/FBdnDhE2HfdDvqy+FOSRnNLWWYeqQFlnCugWaqQJMdYprBFiexZrGb\n" +
                "ARuC50RxcSINE6YBsH1BLLmvd4ZtHba1R8qE9JgJyOj4WtPd3eevWBUJxb32TkZr\n" +
                "CM1oz/Vc7z9/ITk/x+F6YBB1pESUARi6cjelv1x7SN8x3eixApn/K4MCAwEAAaMh\n" +
                "MB8wHQYDVR0OBBYEFKJUpytOnb0vBqrp/y9q0vKbdK4UMA0GCSqGSIb3DQEBCwUA\n" +
                "A4IBAQB00YDYqWt04irjGUFYMrMyZgBCZbCsglQ7NppIeRQ3/rFhM5ivUVEbOS13\n" +
                "x2H8roOS3OWfuCiME06mF9cG8mhqUeiRvGFh9MDFwJmxpqD6jcrwvPMpUCQSONG/\n" +
                "gVozxLbmsFZl9fUITj0h20+jnZbx2yCucJGHxdAtPXyw2MDG2IlRJB7M94j4Gp4O\n" +
                "T2rZ7EjId0MQl7reGigr7XLR6l0djzTBkfbHBtzoH9VQNNjG70GEqzZSQC814RDy\n" +
                "YY5/SuQo5TEyIlrNoWVOs/Y5vXyUrJYlmo/O7uBOFz6kP80SFofbblsqxFY44KP5\n" +
                "/fV+rswMvNvTncFy9HyR7AqZ5XVK\n" +
                "-----END CERTIFICATE-----";

        byte[] encoded = Base64.decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
}
