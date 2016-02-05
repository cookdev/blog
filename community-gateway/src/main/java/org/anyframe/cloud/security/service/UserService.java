package org.anyframe.cloud.security.service;


import org.anyframe.cloud.security.dto.UserAccountDto;

import java.util.Collection;

/**
 * Created by Hahn on 2015-12-04.
 */
public interface UserService {

    UserAccountDto getUserById(String id);

    Collection<UserAccountDto> getAllUsers();

    UserAccountDto create(UserAccountDto userAccountDto);

    void passwordReset(UserAccountDto userAccount);

    void removeUser(String userId);
}
