package ch.m183.session.service;

import java.util.Optional;

import ch.m183.session.model.Account;

public interface IAccountService {
	Account addAccount(Account newAccount);

	Account updateAccount(Account account);

	void deleteAccount(long accountId);

	Optional<Account> getAccountById(Long id);

	Optional<Account> findName(String name);
}
