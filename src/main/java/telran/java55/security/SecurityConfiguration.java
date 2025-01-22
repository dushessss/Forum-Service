package telran.java55.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

import telran.java55.accounting.model.Role;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    WebExpressionAuthorizationManager ownerCheck = new WebExpressionAuthorizationManager(
        "authentication.name.equals(#login)");
    WebExpressionAuthorizationManager authorCheck = new WebExpressionAuthorizationManager(
        "authentication.name.equals(#author)");
    http.httpBasic(Customizer.withDefaults());
    http.csrf(csrf -> csrf.disable());
    http.authorizeHttpRequests(authorize -> authorize
        .requestMatchers("/account/register", "/forum/posts/**").permitAll()
        .requestMatchers("/account/user/{login}/role/{role}").hasRole(Role.ADMINISTRATOR.name())
        .requestMatchers(HttpMethod.DELETE, "/account/user/{login}").access(AuthorizationManagers.anyOf(
            AuthorityAuthorizationManager.hasRole(Role.ADMINISTRATOR.name()),
            ownerCheck))
        .requestMatchers(HttpMethod.PUT, "/account/user/{login}").access(ownerCheck)
        .requestMatchers(HttpMethod.POST, "/forum/post/{author}").access(authorCheck)
        .anyRequest().authenticated());
    return http.build();
  }
  
}