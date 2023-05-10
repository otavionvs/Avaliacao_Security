package br.org.sesisenai.clinipet.security;

import br.org.sesisenai.clinipet.security.service.JpaService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@AllArgsConstructor
public class AutenticacaoConfig {

    private JpaService jpaService;


    // Configura as autorizações de acesso
    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(jpaService)
                .passwordEncoder(new BCryptPasswordEncoder());
//                .passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

//    // Configura o Cors
//    private CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration corsConfiguration =
//                new CorsConfiguration();
//        corsConfiguration.setAllowedOrigins(List.of(
//                "http://localhost:4200"
//        ));
//        corsConfiguration.setAllowedMethods(List.of(
//                "POST", "DELETE", "GET", "PUT"
//        ));
//        corsConfiguration.setAllowCredentials(true);
//        corsConfiguration.setAllowedHeaders(List.of("*"));
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", corsConfiguration);
//        return source;
//    }

    @Bean
    protected SecurityFilterChain configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests()
                .requestMatchers( "/api/login",
                        "/api/logout",
                        "/logout",
                        "/login").permitAll()
                .requestMatchers(HttpMethod.GET, "/animal/*", "/animal", "/atendente/*", "/atendente")
                .hasAnyAuthority("Atendente", "Veterinario")
                .requestMatchers(HttpMethod.POST, "/animal", "/agenda", "/cliente")
                .hasAuthority("Atendente")
                .requestMatchers(HttpMethod.PUT, "/animal/*", "/agenda/*", "/cliente/*")
                .hasAnyAuthority("Atendente", "Veterinario")
                .requestMatchers(HttpMethod.DELETE, "/animal/*", "/agenda/*", "/cliente/*")
                .hasAnyAuthority("Atendente", "Veterinario")


                .requestMatchers(HttpMethod.GET, "/agenda/*", "/agenda", "/prontuario/*", "/prontuario")
                .hasAnyAuthority("Atendente", "Veterinario", "Cliente")


                .requestMatchers(HttpMethod.POST, "/prontuario", "/atendente", "/veterinario", "/servico")
                .hasAuthority("Veterinario")
                .requestMatchers(HttpMethod.PUT, "/prontuario/*", "/atendente/*", "/veterinario/*", "/servico/*")
                .hasAuthority("Veterinario")
                .requestMatchers(HttpMethod.DELETE, "/prontuario/*", "/atendente/*", "/veterinario/*", "/servico/*")
                .hasAuthority("Veterinario")

//                .requestMatchers(HttpMethod.GET, "/cliente/*")
//                .hasAnyAuthority("Atendente", "Veterinario", "Cliente")

                .requestMatchers(HttpMethod.GET, "/veterinario/*", "/veterinario", "/servico/*", "/servico")
                .permitAll()

                .anyRequest().authenticated()
                .and().csrf().disable()
//                .cors().configurationSource(corsConfigurationSource())
                .logout().deleteCookies("token").permitAll()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().addFilterBefore(new AutenticacaoFiltro(new TokenUtils(), jpaService), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
    //Serve pra poder fazer a injeção de dependência na controller
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration ac) throws Exception {
        return ac.getAuthenticationManager();
    }
}
