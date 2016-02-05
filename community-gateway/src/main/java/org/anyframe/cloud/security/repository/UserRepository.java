package org.anyframe.cloud.security.repository;


import org.anyframe.cloud.security.repository.domain.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Spring Data JPA repository for the UserAccountDto entity.
 */
public interface UserRepository extends JpaRepository<UserAccount, String> {
}
