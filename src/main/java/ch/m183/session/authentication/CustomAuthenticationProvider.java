package ch.m183.session.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import ch.m183.session.model.Account;
import ch.m183.session.model.Role;
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

			// d41d8cd98f00b204e9800998ecf8427e  TODO may be I should remove this once
		/* 	Removed the backdoor. */
		Optional<Account> accountByName = accountRepository.findAccountByName(name);

		Account account = accountByName.orElseThrow(() -> new BadCredentialsException("Account not found:" + name));
		// 3de47a0c26dcbfde469206be4bd55865 TODO Password security we should introduce salt
		/* 	Generating Salt for a hashed password */
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[64];
		random.nextBytes(salt);
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		md.update(salt);

		// 838ece1033bf7c7468e873e79ba2a3ec TODO Password security we should encrypt passwords
		/* 	hashing the password -> this need to be done before saving the password into the database, however in this project, the database
		* 	is getting dropped and re-created with every install. */
		byte[] hashedPassword1 = md.digest(password.getBytes(StandardCharsets.UTF_8));



		if (account.getName().equals(name) && account.getPw().equals(password)) {
			// 0cc175b9c0f1b6a831c399e269772661 TODO Roles somehow aren't assigned
			/* ROLE_PREFIX was created, the roles now are checked during the login process. User roles and rights are
			* 	getting assigned. */
			String ROLE_PREFIX = "ROLE_";
			List<SimpleGrantedAuthority> authorities = account.getRoles().stream()
					.map(Role::getName)
					.map(x -> ROLE_PREFIX + x)
					.map(SimpleGrantedAuthority::new)
					.collect(Collectors.toList());
			return new UsernamePasswordAuthenticationToken(
					account.getName(),
					account.getPw(),
					authorities);

		}
		// 4124bc0a9335c27f086f24ba207a4912 TODO 4124bc0a9335c27f086f24ba207a4912 may be we should improve the logging?
		/*	Removed the password from getting logged in the logs. */
		log.info(String.format("password not matched for account %s", name));
		throw new BadCredentialsException("Account not found: " + name);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(UsernamePasswordAuthenticationToken.class);
	}
}
