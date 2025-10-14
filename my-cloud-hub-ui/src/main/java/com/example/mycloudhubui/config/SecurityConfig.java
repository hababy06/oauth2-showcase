package com.example.mycloudhubui.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // ✅ Logger 定義在類別的最上方
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, 
                                                   @org.springframework.beans.factory.annotation.Qualifier("userAuthoritiesMapper") 
                                                   GrantedAuthoritiesMapper authoritiesMapper) throws Exception {
        CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName(null);

        http
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        .csrfTokenRepository(tokenRepository)
                        .csrfTokenRequestHandler(requestHandler)
                        .ignoringRequestMatchers("/login/oauth2/code/**")
                )
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userAuthoritiesMapper(authoritiesMapper)
                        )
                );

        return http.build();
    }

    private static final class CsrfCookieFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain)
                throws ServletException, IOException {
            CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
            if (csrfToken != null) {
                csrfToken.getToken();
            }
            filterChain.doFilter(request, response);
        }
    }

    // ==================== Spring Authorization Server 配置 ====================
    @Bean(name = "userAuthoritiesMapper")
    @ConditionalOnProperty(name = "auth.type", havingValue = "spring-authz", matchIfMissing = true)
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                    mappedAuthorities.add(oidcUserAuthority);

                    logger.info("=== Spring Authorization Server 權限提取 ===");
                    logger.info("用戶: {}", oidcUserAuthority.getIdToken().getPreferredUsername());
                    
                    // ✅ 從 Spring Authorization Server 的 authorities claim 提取權限
                    List<String> customAuthorities = oidcUserAuthority.getIdToken().getClaim("authorities");
                    if (customAuthorities != null) {
                        logger.info("找到 authorities claim: {}", customAuthorities);
                        mappedAuthorities.addAll(customAuthorities.stream()
                                .map(SimpleGrantedAuthority::new)
                                .collect(Collectors.toList()));
                    }
                    
                    logger.info("最終權限: {}", mappedAuthorities.stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()));
                    logger.info("=== Spring Authorization Server 權限提取完成 ===");
                    
                } else {
                    mappedAuthorities.add(authority);
                }
            });

            return mappedAuthorities;
        };
    }

    // ==================== Keycloak 配置 ====================
    @Bean(name = "userAuthoritiesMapper")
    @ConditionalOnProperty(name = "auth.type", havingValue = "keycloak")
    public GrantedAuthoritiesMapper keycloakUserAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                    mappedAuthorities.add(oidcUserAuthority);

                    logger.info("=== Keycloak 權限提取 ===");
                    logger.info("用戶: {}", oidcUserAuthority.getIdToken().getPreferredUsername());
                    
                    // ✅ 從 Keycloak 的 realm_access.roles 提取權限
                    Map<String, Object> realmAccess = oidcUserAuthority.getIdToken().getClaim("realm_access");
                    if (realmAccess != null) {
                        List<String> realmRoles = (List<String>) realmAccess.get("roles");
                        if (realmRoles != null) {
                            logger.info("Realm 角色: {}", realmRoles);
                            mappedAuthorities.addAll(realmRoles.stream()
                                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                    .collect(Collectors.toList()));
                        }
                    }
                    
                    // ✅ 從 Keycloak 的 resource_access.{client-id}.roles 提取權限
                    Map<String, Object> resourceAccess = oidcUserAuthority.getIdToken().getClaim("resource_access");
                    if (resourceAccess != null) {
                        Map<String, Object> clientResource = (Map<String, Object>) resourceAccess.get("my-cloud-hub-ui");
                        if (clientResource != null) {
                            List<String> clientRoles = (List<String>) clientResource.get("roles");
                            if (clientRoles != null) {
                                logger.info("Client 角色: {}", clientRoles);
                                mappedAuthorities.addAll(clientRoles.stream()
                                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                        .collect(Collectors.toList()));
                            }
                        }
                    }
                    
                    logger.info("最終權限: {}", mappedAuthorities.stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList()));
                    logger.info("=== Keycloak 權限提取完成 ===");
                    
                } else {
                    mappedAuthorities.add(authority);
                }
            });

            return mappedAuthorities;
        };
    }
}
