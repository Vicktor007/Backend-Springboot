//package com.zosh.config;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.security.Keys;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.AuthorityUtils;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import javax.crypto.SecretKey;
//import java.io.IOException;
//import java.util.List;
//
//
//public class CookieValidator extends OncePerRequestFilter {
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//        String jwt = null;
//
//        // Retrieve JWT from cookies and validate the cookie
//        if (request.getCookies() != null) {
//            for (Cookie cookie : request.getCookies()) {
//                if ("jwt".equals(cookie.getName()) && isCookieValid(cookie)) {
//                    jwt = cookie.getValue();
//                    break;
//                }
//            }
//        }
//
//        // Check if the cookie is valid
//        if (jwt != null) {
//            try {
//                SecretKey key = Keys.hmacShaKeyFor(JwtConstant.SECRET_KEY.getBytes());
//
//                Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();
//
//                String email = String.valueOf(claims.get("email"));
//
//                String authorities = String.valueOf(claims.get("authorities"));
//
//                System.out.println("authorities -------- " + authorities);
//
//                List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);
//                Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, auths);
//
//                SecurityContextHolder.getContext().setAuthentication(authentication);
//
//            } catch (InvalidTokenException e) {
//                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
//                return;
//            }
//        }
//        filterChain.doFilter(request, response);
//    }
//
//    public static boolean isCookieValid(Cookie cookie) {
//        // Check if the cookie is expired
//        long maxAge = cookie.getMaxAge();
//        long creationTime = System.currentTimeMillis() - (maxAge * 1000);
//        return System.currentTimeMillis() < creationTime + (maxAge * 1000);
//    }
//
//    public static class InvalidTokenException extends RuntimeException {
//        public InvalidTokenException(String message) {
//            super(message);
//        }
//    }
//}
