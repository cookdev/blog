package org.anyframe.cloud.security.rest;

import org.anyframe.cloud.security.dto.UserAccountDto;
import org.anyframe.cloud.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

/**
 * Created by Hahn on 2015-12-04.
 */
@RestController
@RequestMapping(value="/security")
public class RegistrationController {

    @Autowired
    private UserService userService;

    @RequestMapping(value="/register", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    public void registUser(@RequestBody UserAccountDto userAccount){

        userService.create(userAccount);
    }

    @RequestMapping(value="/password", method = RequestMethod.PUT)
    @ResponseStatus(HttpStatus.OK)
    public void passwordReset(@RequestBody UserAccountDto userAccount){
        userService.passwordReset(userAccount);
    }

    @RequestMapping(value="/user/{userId}", method = RequestMethod.DELETE)
    @ResponseStatus(HttpStatus.OK)
    public void removeUser(@PathVariable String userId){
        userService.removeUser(userId);
    }
}
