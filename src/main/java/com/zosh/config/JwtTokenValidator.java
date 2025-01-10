package com.zosh.config;

import com.zosh.repository.TokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenValidator extends OncePerRequestFilter {

	@Autowired
	private TokenRepository tokenRepository;

	@Override
	protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
			throws ServletException, IOException {
		String jwt = request.getHeader(JwtConstant.JWT_HEADER);

		if (jwt != null) {
			jwt = jwt.substring(7);

			try {
				SecretKey key = Keys.hmacShaKeyFor(JwtConstant.SECRET_KEY.getBytes());

				Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt).getPayload();

				String email = String.valueOf(claims.get("email"));

				Date expirationDate = claims.getExpiration();

				if (isTokenExpired(expirationDate)) {
					throw new RuntimeException("Token has expired");
				}

				String authorities = String.valueOf(claims.get("authorities"));

				System.out.println("authorities -------- " + authorities);

				List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);
				Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, auths);

				SecurityContextHolder.getContext().setAuthentication(authentication);

			} catch (Exception e) {
				throw new RuntimeException("Invalid token...");
			}
		}
		filterChain.doFilter(request, response);
	}

	private boolean isTokenExpired(Date expirationDate) {
		return expirationDate.before(new Date());
	}


	public boolean isValid(String token) {

        return tokenRepository
                .findByAccessToken(token)
                .map(t -> !t.isLoggedOut())
                .orElse(false);
	}

}
