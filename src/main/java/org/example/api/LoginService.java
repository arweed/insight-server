package org.example.api;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;
import static io.jsonwebtoken.SignatureAlgorithm.PS512;
import static java.lang.String.format;
import static java.nio.file.Files.readAllBytes;
import static java.nio.file.Paths.get;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static org.example.api.Headers.PASSWORD;
import static org.example.api.Headers.USER_ID;
import static org.example.utilities.Strings.*;

@Path("/login")
public class LoginService {

    private static final Logger logger = LoggerFactory.getLogger(LoginService.class);

    private static final long EXPIRATION_LIMIT_IN_MINUTES = 30;

    @POST
    @Produces(APPLICATION_JSON)
    public Response login(@HeaderParam(USER_ID)String userId, @HeaderParam(PASSWORD)String password) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        if (isEmpty(userId) || isEmpty(password)) {
            return Response.status(BAD_REQUEST.getStatusCode(), "userid or password empty").build();
        }

        // todo verify credentials
        
        String token = buildJwt(userId);
        logger.info(format("User %s logged in, token %s", userId, token));
        return Response.ok(token).build();
    }

    private String buildJwt(String userId) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        return Jwts.builder()
                .setSubject(userId)
                .setExpiration(newExpirationDate())
                .signWith(loadPrivateKey(), PS512)
                .setIssuedAt(new Date())
                .compact();
    }

    private PrivateKey loadPrivateKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] bytes = LoginService.class.getResourceAsStream("/keys/private.key").readAllBytes();
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpecPKCS8);
    }

    private Date newExpirationDate() {
        long currentTimeInMillis = System.currentTimeMillis();
        long expMilliSeconds = TimeUnit.MINUTES.toMillis(EXPIRATION_LIMIT_IN_MINUTES);
        return new Date(currentTimeInMillis + expMilliSeconds);
    }
}
