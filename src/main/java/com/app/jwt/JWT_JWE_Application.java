package com.app.jwt;

import com.app.jwt.config.PrivateKeyProperties;
import com.app.jwt.config.PublicKeyProperties;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class JWT_JWE_Application {

	public static void main(String[] args) throws Exception {
		decryptJWT();
	}

	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

		// instantiate KeyPairGenerate with RSA algorithm.
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");

		// set the key size to 2048 bits.
		keyGenerator.initialize(2048);

		// generate and return private/public key pair.
		return keyGenerator.genKeyPair();
	}

	public static String buildEncryptedJWT(PublicKey publicKey) throws JOSEException {

		// build audience restriction list.
		List<String> aud = new ArrayList<String>();
		aud.add("*.ecommm.com");

		Date currentTime = new Date();

		// create a claim set.
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().
				// set the value of the issuer.
						issuer("sts.ecomm.com").
				// set the subject value - JWT belongs to this subject.
						subject("panindra").
				// set values for audience restriction.
						audience(aud).
				// expiration time set to 10 minutes.
						expirationTime(new Date(new Date().getTime() + 1000 * 60 * 10)).
				// set the valid from time to current time.
						notBeforeTime(currentTime).
				// set issued time to current time.
						issueTime(currentTime).
				// set a generated UUID as the JWT identifier.
						jwtID(UUID.randomUUID().toString()).build();

		// create JWE header with RSA-OAEP and AES/GCM.
		JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);

		// create encrypter with the RSA public key.
		JWEEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);

		// create the encrypted JWT with the JWE header and the JWT payload.
		EncryptedJWT encryptedJWT = new EncryptedJWT(jweHeader, jwtClaims);

		// encrypt the JWT.
		encryptedJWT.encrypt(encrypter);

		// serialize into base64-encoded text.
		String jwtInText = encryptedJWT.serialize();

		// print the value of the JWT.
		System.out.println(jwtInText);
		System.out.println();

		return jwtInText;
	}

	public static void decryptJWT() throws Exception {

		// generate private/public key pair.
		//KeyPair keyPair = generateKeyPair();

		// get the private key - used to decrypt the message.
		PrivateKey privateKey = PrivateKeyProperties.readPrivateKey();

		// get the public key - used to encrypt the message.
		PublicKey publicKey = PublicKeyProperties.readPublicKey();

		Base64.Encoder encoder = Base64.getEncoder();

		System.out.println("Private key content: " + encoder.encodeToString(privateKey.getEncoded()));
		System.out.println();
		System.out.println("Public key content: " + encoder.encodeToString(publicKey.getEncoded()));
		System.out.println();


		// get encrypted JWT in base64-encoded text.
		String jwtInText = buildEncryptedJWT(publicKey);

		// create a decrypter.
		JWEDecrypter decrypter = new RSADecrypter((RSAPrivateKey) privateKey);

		// create the encrypted JWT with the base64-encoded text.
		EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwtInText);

		// decrypt the JWT.
		encryptedJWT.decrypt(decrypter);

		// print the value of JOSE header.

		System.out.println("JWE Header:" + encryptedJWT.getHeader());
		System.out.println();

		// JWE content encryption key.
		System.out.println("JWE Content Encryption Key: " + encryptedJWT.getEncryptedKey());
		System.out.println();

		// initialization vector.
		System.out.println("Initialization Vector: " + encryptedJWT.getIV());
		System.out.println();

		// ciphertext.
		System.out.println("Ciphertext : " + encryptedJWT.getCipherText());
		System.out.println();

		// authentication tag.
		System.out.println("Authentication Tag: " + encryptedJWT.getAuthTag());
		System.out.println();

		// print the value of JWT body
		System.out.println("Decrypted Payload: " + encryptedJWT.getPayload());
		System.out.println();
	}

}
