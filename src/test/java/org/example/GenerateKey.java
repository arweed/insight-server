package org.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.file.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import static io.jsonwebtoken.SignatureAlgorithm.PS512;
import static java.nio.file.Files.readAllBytes;
import static java.nio.file.Paths.get;
import static java.nio.file.StandardOpenOption.CREATE_NEW;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Disabled
public class GenerateKey {

    @Test
    public void generateRsa() throws Exception {
        // 4096bit, pkcs8 format (private key), x509 format (public key)
        KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.PS512);

        Path pkey = get("c:", "temp","private.key");
        Files.write(pkey,keyPair.getPrivate().getEncoded(), CREATE_NEW);

        Path pubkey = get("c:", "temp","public.key");
        Files.write(pubkey,keyPair.getPublic().getEncoded(), CREATE_NEW);
    }

    @Test
    public void loadKeys() throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(readAllBytes(get("c:", "temp", "private.key")));
        PrivateKey privKey = factory.generatePrivate(keySpecPKCS8);
        assertNotNull(privKey);
    }

    @Test
    public void verify() throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(readAllBytes(get("c:", "temp", "private.key")));
        PrivateKey privateKey = factory.generatePrivate(privateKeySpec);

        String token = Jwts.builder().setSubject("userId").signWith(privateKey, PS512).compact();

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(readAllBytes(get("c:", "temp", "public.key")));
        PublicKey publicKey = factory.generatePublic(publicKeySpec);

        Jws<Claims> claimsJws = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token);
        System.out.println();
    }
}
