package bd.pai_testjwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    @Autowired
    private UserDetailsService jwtUserDetailsService;
    @Autowired
    private JwtRequestFilter jwtRequestFilter;
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth)
            throws Exception {
        // Konfiguracja menadżera AuthenticationManager tak, aby
        // wiedział skąd załadować użytkownika w celu dopasowania
        // danych uwierzytelniających
        // Zastosowano haszowanie hasła za pomocą BCryptPasswordEncoder
        auth.userDetailsService(jwtUserDetailsService).
                passwordEncoder(passwordEncoder());
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean()
            throws Exception {
        return super.authenticationManagerBean();
    }
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception
    {
        // W tym przykładzie nie potrzebne jest zabezpieczenie CSRF
        httpSecurity.csrf().disable()
                // te żądania nie wymagają uwierzytelniania
                .authorizeRequests().antMatchers("/authenticate")
                .permitAll().
                // pozostałe żądania wymagają uwierzytelniania
                        anyRequest().authenticated().and()
                // zastosowana sesja bezstanowa - sesja nie przechowuje
                // stanu użytkownika.
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint).and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // Dodanie filtra do walidacji tokena przy każdym żądaniu
        httpSecurity.addFilterBefore(jwtRequestFilter,
                UsernamePasswordAuthenticationFilter.class);
    }
}