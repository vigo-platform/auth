package ir.vigoapp.auth.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import ir.vigoapp.auth.dto.ApiResponse;
import ir.vigoapp.auth.service.SessionService;
import ir.vigoapp.auth.service.login.ClientInfo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private final JwtDecoder jwtDecoder;
    private final SessionService sessions;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        String token = resolveToken(request);

        if (token != null) {
            var client = ClientInfo.from(request);
            try {
                Jwt jwt = jwtDecoder.decode(token);
                if (sessions.isAccessSessionActive(jwt)) {
                    List<String> roles = jwt.getClaimAsStringList("roles");
                    var authorities = roles == null ? List.<SimpleGrantedAuthority>of() : roles.stream()
                            .map(role -> new SimpleGrantedAuthority(role.startsWith("ROLE_") ? role : "ROLE_" + role)).toList();
                    SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, authorities));
                    log.atDebug().addKeyValue("event", "jwt_authenticated").addKeyValue("user_id", jwt.getSubject())
                            .addKeyValue("session_id", jwt.getClaimAsString("sid")).addKeyValue("ip_address", client.ipAddress())
                            .log("Access token authenticated.");
                }
            } catch (JwtException e) {
                SecurityContextHolder.clearContext();
                log.atDebug().addKeyValue("event", "jwt_rejected").addKeyValue("reason", "invalid_token")
                        .addKeyValue("ip_address", client.ipAddress()).addKeyValue("path", request.getRequestURI())
                        .log("Invalid access token rejected.");
            } catch (DataAccessException e) {
                SecurityContextHolder.clearContext();
                log.atError().addKeyValue("event", "access_session_check_failed").addKeyValue("status", 503)
                        .addKeyValue("reason", e.getClass().getSimpleName()).addKeyValue("ip_address", client.ipAddress())
                        .addKeyValue("http_method", request.getMethod()).addKeyValue("path", request.getRequestURI())
                        .log("Access session could not be checked.");
                response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
                objectMapper.writeValue(response.getOutputStream(), ApiResponse.failure("AUTH_SERVICE_UNAVAILABLE",
                        "Authentication is temporarily unavailable.", "سرویس احراز هویت موقتاً در دسترس نیست.", null));
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length()).trim();
        }
        return null;
    }
}
