package ch.m183.session.repository;

import java.util.Optional;

import ch.m183.session.model.Account;
import org.springframework.data.repository.CrudRepository;

/**
 * Jup a Repository
 */
public interface AccountRepository extends CrudRepository<Account, Long> {

	/**
	 * @param name to search for
	 * @return a account if matched
	 */
	Optional<Account> findAccountByName(String name);
}
