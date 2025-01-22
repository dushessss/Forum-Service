package telran.java55.accounting.dao;

import org.springframework.data.mongodb.repository.MongoRepository;

import telran.java55.accounting.model.UserAccount;

public interface UserAccountRepository extends MongoRepository<UserAccount, String> {


}

