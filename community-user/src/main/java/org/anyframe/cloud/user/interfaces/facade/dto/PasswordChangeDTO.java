package org.anyframe.cloud.user.interfaces.facade.dto;

/**
 * Created by SDS on 2015-12-03.
 */
public class PasswordChangeDTO {
    String userId;
    String password;
    String existPassword;

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

    public String getExistPassword() {
        return existPassword;
    }

    public void setExistPassword(String existPassword) {
        this.existPassword = existPassword;
    }
}
