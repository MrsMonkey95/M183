package ch.m183.session.config;

import ch.m183.session.authentication.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * security config to define where which roles & rules apply.
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	public static final String H2_CONSOLE = "/h2-console/**";
	public static final String FAVICON_ICO = "/favicon.ico";
	public static final String ROLE_ADMIN = "ADMIN";
	public static final String ROLE_USER = "USER";

	@Autowired
	private CustomAuthenticationProvider authProvider;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authProvider);
	}
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/hello-admin").hasAnyRole(ROLE_ADMIN)
				// eb9b97d67e70c8868256b5d3e048d2ca TODO find out why admin has no access
				.antMatchers("/hello-user").hasAnyRole(ROLE_USER)
				.antMatchers("/", "/home", H2_CONSOLE, FAVICON_ICO, "/css/**", "/js/**").permitAll()
				.anyRequest().authenticated()
			.and()
				.formLogin()
				.loginPage("/login")
				.permitAll()
			.and()
				.logout()
				.permitAll();
	}

}
