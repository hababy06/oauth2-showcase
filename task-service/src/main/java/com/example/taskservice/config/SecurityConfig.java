package com.example.taskservice.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, 
                                                   @org.springframework.beans.factory.annotation.Qualifier("jwtAuthenticationConverter") 
                                                   JwtAuthenticationConverter jwtConverter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtConverter)
                        )
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    // ==================== Spring Authorization Server 配置 ====================
    @Bean(name = "jwtAuthenticationConverter")
    @ConditionalOnProperty(name = "auth.type", havingValue = "spring-authz", matchIfMissing = true)
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        System.out.println("✅ 載入 Spring Authorization Server 的 JWT 配置");
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        // ✅ Spring Authorization Server：從 authorities claim 讀取
        grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
        grantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }

    // ==================== Keycloak 配置 ====================
    @Bean(name = "jwtAuthenticationConverter")
    @ConditionalOnProperty(name = "auth.type", havingValue = "keycloak")
    public JwtAuthenticationConverter keycloakJwtAuthenticationConverter() {
        System.out.println("✅ 載入 Keycloak 的 JWT 配置");
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(keycloakGrantedAuthoritiesConverter());
        return jwtAuthenticationConverter;
    }

    @Bean
    @ConditionalOnProperty(name = "auth.type", havingValue = "keycloak")
    public Converter<Jwt, Collection<GrantedAuthority>> keycloakGrantedAuthoritiesConverter() {
        return new Converter<Jwt, Collection<GrantedAuthority>>() {
            @Override
            public Collection<GrantedAuthority> convert(Jwt jwt) {
                Collection<GrantedAuthority> authorities = new HashSet<>();

                System.out.println("=== Keycloak JWT 權限提取 ===");
                System.out.println("JWT Claims: " + jwt.getClaims());

                // ✅ Keycloak：從 realm_access.roles 提取
                Map<String, Object> realmAccess = jwt.getClaim("realm_access");
                if (realmAccess != null) {
                    Object rolesObj = realmAccess.get("roles");
                    if (rolesObj != null) {
                        List<String> realmRoles;
                        if (rolesObj instanceof List) {
                            realmRoles = (List<String>) rolesObj;
                        } else if (rolesObj instanceof String) {
                            // 如果是單個字串，轉換為 List
                            realmRoles = List.of((String) rolesObj);
                        } else {
                            realmRoles = new ArrayList<>();
                        }
                        System.out.println("Realm 角色: " + realmRoles);
                        authorities.addAll(realmRoles.stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                .collect(Collectors.toList()));
                    }
                }

                // ✅ Keycloak：從 resource_access.{client-id}.roles 提取
                Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
                if (resourceAccess != null) {
                    Map<String, Object> clientResource = (Map<String, Object>) resourceAccess.get("my-cloud-hub-ui");
                    if (clientResource != null) {
                        Object clientRolesObj = clientResource.get("roles");
                        if (clientRolesObj != null) {
                            List<String> clientRoles;
                            if (clientRolesObj instanceof List) {
                                clientRoles = (List<String>) clientRolesObj;
                            } else if (clientRolesObj instanceof String) {
                                // 如果是單個字串，轉換為 List
                                clientRoles = List.of((String) clientRolesObj);
                            } else {
                                clientRoles = new ArrayList<>();
                            }
                            System.out.println("Client 角色: " + clientRoles);
                            authorities.addAll(clientRoles.stream()
                                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                    .collect(Collectors.toList()));
                        }
                    }
                }

                // ✅ 保留預設的 scope 權限
                JwtGrantedAuthoritiesConverter defaultConverter = new JwtGrantedAuthoritiesConverter();
                authorities.addAll(defaultConverter.convert(jwt));

                System.out.println("最終權限: " + authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()));
                System.out.println("=== Keycloak 權限提取完成 ===");

                return authorities;
            }
        };
    }
}