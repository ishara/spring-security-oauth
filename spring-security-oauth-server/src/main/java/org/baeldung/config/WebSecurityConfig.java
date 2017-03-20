package org.baeldung.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public void globalUserDetails(final AuthenticationManagerBuilder auth) throws Exception {
        // @formatter:off
//		auth.inMemoryAuthentication().withUser("john").password("123").roles("USER").and().withUser("tom")
//				.password("111").roles("ADMIN");
        auth.authenticationProvider( customAuthenticationProvider() );
        // @formatter:on
        //todo add customAuthenticationProvider
    }
    @Bean
    AuthenticationProvider customAuthenticationProvider() {
        CustomAuthenticationProvider impl = new CustomAuthenticationProvider();
        return impl ;
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        // @formatter:off
		http.authorizeRequests()
                .antMatchers("/login").permitAll().anyRequest().authenticated().and().formLogin()
				.permitAll();
        http.authorizeRequests().antMatchers( "/oauth/revoke-token" ).permitAll().anyRequest().anonymous();
//        http.csrf().disable();
//        http.csrf().csrfTokenRepository( CookieCsrfTokenRepository.withHttpOnlyFalse());
        // @formatter:on
    }

}
