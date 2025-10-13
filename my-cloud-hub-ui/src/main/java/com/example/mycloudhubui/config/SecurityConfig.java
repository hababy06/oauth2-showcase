package com.example.mycloudhubui.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // ✅ CSRF Token配置
        CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName(null);  // 關閉延遲載入

        http
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        .csrfTokenRepository(tokenRepository)
                        .csrfTokenRequestHandler(requestHandler)
                        // ✅ 忽略OAuth2回調路徑，避免Session切換時Token失效
                        .ignoringRequestMatchers("/login/oauth2/code/**")
                )
                // ✅ 確保每個請求都生成Token到Cookie
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                // ✅ 從ID Token中提取authorities到Spring Security權限
                                .userAuthoritiesMapper(userAuthoritiesMapper())
                        )
                );

        return http.build();
    }

    /**
     * ✅ CSRF Token過濾器：確保Token總是寫入Cookie
     * 解決OAuth2登入後Session切換導致的Token失效問題
     */
    private static final class CsrfCookieFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain)
                throws ServletException, IOException {
            CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
            if (csrfToken != null) {
                csrfToken.getToken();  // 觸發Token載入並寫入Cookie
            }
            filterChain.doFilter(request, response);
        }
    }

    /**
     * ✅ 權限映射器：從ID Token的authorities claim中提取權限
     * 讓前端Thymeleaf的sec:authorize="hasRole('ADMIN')"能正常工作
     */
    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                // 保留OIDC預設權限
                if (authority instanceof OidcUserAuthority) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                    mappedAuthorities.add(oidcUserAuthority);

                    // ✅ 從ID Token的authorities claim提取自訂權限（Auth Server 模式）
                    List<String> customAuthorities = oidcUserAuthority.getIdToken().getClaim("authorities");
                    if (customAuthorities != null) {
                        mappedAuthorities.addAll(customAuthorities.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList()));
                    }

                    // ✅ 從Keycloak的realm_access.roles提取角色（Keycloak 模式）
                    Object realmAccess = oidcUserAuthority.getIdToken().getClaim("realm_access");
                    if (realmAccess instanceof java.util.Map) {
                        @SuppressWarnings("unchecked")
                        java.util.Map<String, Object> realmAccessMap = (java.util.Map<String, Object>) realmAccess;
                        Object roles = realmAccessMap.get("roles");
                        if (roles instanceof java.util.List) {
                            @SuppressWarnings("unchecked")
                            java.util.List<String> roleList = (java.util.List<String>) roles;
                            mappedAuthorities.addAll(roleList.stream()
                                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                                    .collect(Collectors.toList()));
                        }
                    }

                    // ✅ 從Keycloak的resource_access提取客戶端角色
                    Object resourceAccess = oidcUserAuthority.getIdToken().getClaim("resource_access");
                    if (resourceAccess instanceof java.util.Map) {
                        @SuppressWarnings("unchecked")
                        java.util.Map<String, Object> resourceAccessMap = (java.util.Map<String, Object>) resourceAccess;
                        Object clientAccess = resourceAccessMap.get("my-cloud-hub-ui");
                        if (clientAccess instanceof java.util.Map) {
                            @SuppressWarnings("unchecked")
                            java.util.Map<String, Object> clientAccessMap = (java.util.Map<String, Object>) clientAccess;
                            Object clientRoles = clientAccessMap.get("roles");
                            if (clientRoles instanceof java.util.List) {
                                @SuppressWarnings("unchecked")
                                java.util.List<String> clientRoleList = (java.util.List<String>) clientRoles;
                                mappedAuthorities.addAll(clientRoleList.stream()
                                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                                        .collect(Collectors.toList()));
                            }
                        }
                    }
                } else {
                    mappedAuthorities.add(authority);
                }
            });

            return mappedAuthorities;
        };
    }
}
