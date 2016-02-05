package org.anyframe.cloud.user.interfaces.facade.dto;

/**
 * Created by Hahn on 2015-11-26.
 */
public class PasswordValidationDTO {

    private String userId;
    private String password;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
