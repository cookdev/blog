package org.anyframe.cloud.security.service.impl;


import org.anyframe.cloud.security.dto.UserAccountDto;
import org.anyframe.cloud.security.repository.UserRepository;
import org.anyframe.cloud.security.repository.domain.Authority;
import org.anyframe.cloud.security.repository.domain.UserAccount;
import org.anyframe.cloud.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Created by Hahn on 2015-12-04.
 */
@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Autowired
    public UserServiceImpl(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @Override
    public UserAccountDto getUserById(String id){
        UserAccount userAccount = userRepository.findOne(id);
        return new UserAccountDto(userAccount.getUserId(), userAccount.getPassword(), userAccount.isEnabled(), userAccount.getAuthorities());
    }

    @Override
    public Collection<UserAccountDto> getAllUsers() {

        List<UserAccount> userAccountList = userRepository.findAll();

        List<UserAccountDto> userDtoList = new ArrayList<UserAccountDto>();
        for(UserAccount user: userAccountList){
            userDtoList.add(new UserAccountDto(user.getUserId(), user.getPassword(), user.isEnabled(), user.getAuthorities()));
        }
        return userDtoList;
    }

    @Override
    public UserAccountDto create(UserAccountDto form) {
        UserAccount user = new UserAccount();
        user.setUserId(form.getUserId());
        user.setPassword(form.getPassword());
//        user.setPassword(new BCryptPasswordEncoder().encode(form.getPassword()));
        user.setEnabled(true);
        user.setAuthorities(new HashSet<Authority>());
        user.getAuthorities().add(new Authority("ROLE_USER"));

        UserAccount userAccount = userRepository.save(user);
        return new UserAccountDto(userAccount.getUserId(), userAccount.getPassword(), userAccount.isEnabled(), userAccount.getAuthorities());
    }

    @Override
    public void passwordReset(UserAccountDto userAccount) {
        UserAccount user = new UserAccount();
        user.setUserId(userAccount.getUserId());
        user.setPassword(userAccount.getPassword());
        user.setEnabled(true);

        userRepository.save(user);
    }

    @Override
    public void removeUser(String userId) {

        userRepository.delete(userId);
    }

}