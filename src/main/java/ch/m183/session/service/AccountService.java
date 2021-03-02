package ch.m183.session.service;

import java.util.Optional;

import ch.m183.session.model.Account;
import ch.m183.session.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AccountService implements IAccountService {
	@Autowired
	private AccountRepository accountRepository;

	@Override
	public Account addAccount(Account newAccount) {
		return accountRepository.save(newAccount);
	}

	@Override
	public Account updateAccount(Account account) {
		return accountRepository.save(account);
	}

	@Override
	public void deleteAccount(long accountId) {
		accountRepository.deleteById(accountId);
	}

	@Override
	public Optional<Account> getAccountById(Long id) {
		return accountRepository.findById(id);
	}

	@Override
	public Optional<Account> findName(String name) {
		return accountRepository.findAccountByName(name);
	}
}
