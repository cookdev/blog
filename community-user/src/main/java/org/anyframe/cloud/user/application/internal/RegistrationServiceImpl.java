package org.anyframe.cloud.user.application.internal;

import org.anyframe.cloud.user.application.RegistrationService;
import org.anyframe.cloud.user.application.exception.IDAlreadyExistException;
import org.anyframe.cloud.user.application.exception.PasswordIsWrongException;
import org.anyframe.cloud.user.application.exception.UserIsNotExistException;
import org.anyframe.cloud.user.domain.RegisteredUser;
import org.anyframe.cloud.user.infrastructure.persistence.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Created by Hahn on 2015-11-25.
 */
@Service
public class RegistrationServiceImpl implements RegistrationService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public RegisteredUser registerNewUser(RegisteredUser newUser) {
        RegisteredUser registeredUser;

        //ID Check
        if(isExistUser(newUser.getUserId())){
            throw new IDAlreadyExistException();
        }else{

            registeredUser = userRepository.save(newUser);
        }
        return registeredUser;
    }

    @Override
    public RegisteredUser getUserById(String userId) {

        RegisteredUser user = userRepository.findOne(userId);

        if(user == null){
            throw new UserIsNotExistException();
        }

        return user;
    }

    @Override
    public RegisteredUser modifyUser(RegisteredUser registeredUser) {

        RegisteredUser existUser;

        //Exist Check
        if(isExistUser(registeredUser.getUserId())){
            RegisteredUser UserGetPassword = userRepository.getOne(registeredUser.getUserId());
            registeredUser.setPassword(UserGetPassword.getPassword());
            existUser = userRepository.save(registeredUser);
        }else{
            throw new UserIsNotExistException();
        }

        return existUser;
    }

    @Override
    public void deleteUser(String userIdForDelete) {

        //Exist Check
        if(isExistUser(userIdForDelete)){
            userRepository.delete(userIdForDelete);
        }else{
            throw new UserIsNotExistException();
        }

    }

    @Override
    public void validatePassword(RegisteredUser registeredUser) {
        RegisteredUser validatePassword = userRepository.findByUserIdAndPassword(registeredUser.getUserId(), registeredUser.getPassword());
        if(validatePassword == null){
            throw new PasswordIsWrongException();
        }
    }

    @Override
    public RegisteredUser changePassword(RegisteredUser registeredUser, String existPassword) {
        RegisteredUser resultUser;

        //Exist Check
        if(isExistUser(registeredUser.getUserId())){
            RegisteredUser existUser = userRepository.getOne(registeredUser.getUserId());
            if((existUser.getPassword()).equals(existPassword)){
                existUser.setPassword(registeredUser.getPassword());
                resultUser = userRepository.save(existUser);
            }else{
                throw new PasswordIsWrongException();
            }
        }else{
            throw new UserIsNotExistException();
        }

        return resultUser;
    }

    private boolean isExistUser(String userId) {
        RegisteredUser existUser = userRepository.findOne(userId);
        return existUser == null ? false : true;
    }
}
