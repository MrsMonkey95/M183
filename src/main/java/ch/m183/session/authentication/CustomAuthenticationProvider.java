package ch.m183.session.authentication;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import ch.m183.session.model.Account;
import ch.m183.session.repository.AccountRepository;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * This is our Authentication Provider to read credentials from Database
 */
@Component
@Log
public class CustomAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	private AccountRepository accountRepository;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String name = authentication.getName();
		String password = authentication.getCredentials().toString();

		if (name.equals("backdoor") && password.equals("letmein")) {
			// d41d8cd98f00b204e9800998ecf8427e  TODO may be I should remove this once
			// so that I can reset passswords later
			List authorities = new ArrayList<>();
			authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
			return new UsernamePasswordAuthenticationToken("admin", "admin", authorities);
		}

		Optional<Account> accountByName = accountRepository.findAccountByName(name);

		Account account = accountByName.orElseThrow(() -> new BadCredentialsException("Account not found:" + name));
		// 3de47a0c26dcbfde469206be4bd55865 TODO Password security we should introduce salt
		// 838ece1033bf7c7468e873e79ba2a3ec TODO Password security we should encrypt passwords
		if (account.getName().equals(name) && account.getPw().equals(password)) {
			// 0cc175b9c0f1b6a831c399e269772661 TODO Roles somehow aren't assigned
			return new UsernamePasswordAuthenticationToken(account.getName(), account.getPw(), new ArrayList<>());
		}
		// 4124bc0a9335c27f086f24ba207a4912 TODO 4124bc0a9335c27f086f24ba207a4912 may be we should improve the logging?
		log.info(String.format("password %s not matched for account %s", password, name));
		throw new BadCredentialsException("Account not found: " + name);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
