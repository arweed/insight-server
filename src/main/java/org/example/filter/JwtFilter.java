package org.example.filter;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;
import static org.example.utilities.Strings.isEmpty;

@WebFilter("/*")
public class JwtFilter extends HttpFilter {

    private PublicKey publicKey;

    @Override
    public void init(FilterConfig config) throws ServletException {
        super.init(config);

        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            byte[] bytes = JwtFilter.class.getResourceAsStream("/keys/public.key").readAllBytes();
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytes);
            publicKey = factory.generatePublic(publicKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new ServletException("Couldn't load public key");
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;

        if ("/api/login".equals(request.getRequestURI())) {
            chain.doFilter(req,res);
            return;
        }

        String header = request.getHeader(AUTHORIZATION);
        if (isEmpty(header)) {
            throw new WebApplicationException("Please use the login service to authenticate", UNAUTHORIZED);
        }

        validateToken(header);
        chain.doFilter(req,res);
    }

    private void validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token.replace("Bearer ",""));
        } catch (JwtException e) {
            throw new WebApplicationException("Couldn't authenticate user", UNAUTHORIZED);
        }
    }
}
