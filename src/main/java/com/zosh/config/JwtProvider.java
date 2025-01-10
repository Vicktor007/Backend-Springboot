package com.zosh.config;

import com.zosh.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

@Service
public class JwtProvider {

	@Autowired
	private TokenRepository tokenRepository;


private static final SecretKey key=Keys.hmacShaKeyFor(JwtConstant.SECRET_KEY.getBytes());
	
	public static String generateToken(Authentication auth) {
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
	    String roles = populateAuthorities(authorities);

		String jwt;
        jwt = Jwts.builder()
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime()+86400000))
                .claim("email",auth.getName())
                .claim("authorities", roles)
                .signWith(key)
                .compact();
;
		return jwt;
		
	}
	
	public static String getEmailFromJwtToken(String jwt) {
		jwt=jwt.substring(7);
		
		Claims claims=Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt).getPayload();
		String email;
        email = String.valueOf(claims.get("email"));

        return email;
	}
	
	public static String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
		Set<String> auths=new HashSet<>();
		
		for(GrantedAuthority authority:collection) {
			auths.add(authority.getAuthority());
		}
		return String.join(",",auths);
	}

	public boolean isValid(String token) {

		boolean validToken = tokenRepository
				.findByAccessToken(token)
				.map(t -> !t.isLoggedOut())
				.orElse(false);

		return  !isTokenExpired(token) && validToken;
	}


	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}


	public <T> T extractClaim(String token, Function<Claims, T> resolver) {
		Claims claims = extractAllClaims(token);
		return resolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		return Jwts
				.parser()
				.verifyWith(key)
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}


}
