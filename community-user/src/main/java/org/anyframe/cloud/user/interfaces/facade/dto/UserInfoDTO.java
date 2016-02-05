package org.anyframe.cloud.user.interfaces.facade.dto;

/**
 * Created by Hahn on 2015-11-26.
 */
public class UserInfoDTO {
    private String userId;
    private String userName;
    private String email;
    private String picture;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }
}
