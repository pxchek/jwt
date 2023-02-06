# jwt

Generate Private/Public key pair-The private key is used to sign JWTs and the public key to validate the signature. 

1. Private Key generation

keytool -genkeypair -alias panindraprivatekey -keyalg RSA -keypass abc123 -keystore panindraprivatekey.jks -storepass abc123

Example.
➜  sample01 keytool -genkeypair -alias panindraprivatekey -keyalg RSA -keypass abc123 -keystore panindraprivatekey.jks -storepass abc123

What is your first and last name?
[Unknown]:  Panindra

What is the name of your organizational unit?
[Unknown]:  ecommerce

What is the name of your organization?
[Unknown]:  amazon

What is the name of your City or Locality?
[Unknown]:  Naperville

What is the name of your State or Province?
[Unknown]:  IL

What is the two-letter country code for this unit?
[Unknown]:  US

Is CN=Panindra, OU=ecommerce, O=amazon, L=Naperville, ST=IL, C=US correct?
[no]:  yes

Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 90 days
for: CN=Panindra, OU=ecommerce, O=amazon, L=Naperville, ST=IL, C=US

2. Public key generation

keytool -list -rfc --keystore panindraprivatekey.jks | openssl x509 -inform pem -publickey

➜  sample01 keytool -list -rfc --keystore panindraprivatekey.jks | openssl x509 -inform pem -publickey
Enter keystore password:  abc123

-----BEGIN CERTIFICATE-----
MIIDcTCCAlmgAwIBAgIIE6ZKGVzUUREwDQYJKoZIhvcNAQELBQAwZzELMAkGA1UE
BhMCVVMxCzAJBgNVBAgTAklMMRMwEQYDVQQHEwpOYXBlcnZpbGxlMQ8wDQYDVQQK
EwZhbWF6b24xEjAQBgNVBAsTCWVjb21tZXJjZTERMA8GA1UEAxMIUGFuaW5kcmEw
HhcNMjMwMjA2MDA0MDU3WhcNMjMwNTA3MDA0MDU3WjBnMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCSUwxEzARBgNVBAcTCk5hcGVydmlsbGUxDzANBgNVBAoTBmFtYXpv
bjESMBAGA1UECxMJZWNvbW1lcmNlMREwDwYDVQQDEwhQYW5pbmRyYTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKu244sazYFX94xfZzwnCd07HWycx9t8
AOnSUy4SLH2JMKPGtuc2t+L5hjr+4WCSi3fsDlAeY9FPvXfm5SH7NfW23RFw6fXh
h8nwcC3uonQIzUuFczbdLWjBpncfLkAmSvjJ7IWwqyE3RJCtJrkgfZTlmwDqpNP9
7aZ3h3yhi/FBdnDhE2HfdDvqy+FOSRnNLWWYeqQFlnCugWaqQJMdYprBFiexZrGb
ARuC50RxcSINE6YBsH1BLLmvd4ZtHba1R8qE9JgJyOj4WtPd3eevWBUJxb32TkZr
CM1oz/Vc7z9/ITk/x+F6YBB1pESUARi6cjelv1x7SN8x3eixApn/K4MCAwEAAaMh
MB8wHQYDVR0OBBYEFKJUpytOnb0vBqrp/y9q0vKbdK4UMA0GCSqGSIb3DQEBCwUA
A4IBAQB00YDYqWt04irjGUFYMrMyZgBCZbCsglQ7NppIeRQ3/rFhM5ivUVEbOS13
x2H8roOS3OWfuCiME06mF9cG8mhqUeiRvGFh9MDFwJmxpqD6jcrwvPMpUCQSONG/
gVozxLbmsFZl9fUITj0h20+jnZbx2yCucJGHxdAtPXyw2MDG2IlRJB7M94j4Gp4O
T2rZ7EjId0MQl7reGigr7XLR6l0djzTBkfbHBtzoH9VQNNjG70GEqzZSQC814RDy
YY5/SuQo5TEyIlrNoWVOs/Y5vXyUrJYlmo/O7uBOFz6kP80SFofbblsqxFY44KP5
/fV+rswMvNvTncFy9HyR7AqZ5XVK
-----END CERTIFICATE-----


