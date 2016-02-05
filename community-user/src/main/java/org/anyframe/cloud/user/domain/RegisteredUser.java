package org.anyframe.cloud.user.domain;

import javax.persistence.*;
import java.io.Serializable;

/**
 * Created by Hahn on 2015-11-25.
 */
@Entity
public class RegisteredUser implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @Column(name="user_id")
    private String userId;

    private String userName;

    private String password;

    private String email;

    private String picture;

    public RegisteredUser() {
    }

    public RegisteredUser(String userId) {
        this.userId = userId;
    }

    public RegisteredUser(String userId, String userName, String password, String email, String picture) {
        this.userId = userId;
        this.userName = userName;
        this.password = password;
        this.email = email;
        this.picture = picture;
    }

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

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

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RegisteredUser registeredUser = (RegisteredUser) o;

        if (userId != null ? !userId.equals(registeredUser.userId) : registeredUser.userId != null) return false;
        if (userName != null ? !userName.equals(registeredUser.userName) : registeredUser.userName != null) return false;
        if (password != null ? !password.equals(registeredUser.password) : registeredUser.password != null) return false;
        if (email != null ? !email.equals(registeredUser.email) : registeredUser.email != null) return false;
        return !(picture != null ? !picture.equals(registeredUser.picture) : registeredUser.picture != null);

    }

    @Override
    public int hashCode() {
        int result = userId != null ? userId.hashCode() : 0;
        result = 31 * result + (userName != null ? userName.hashCode() : 0);
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + (email != null ? email.hashCode() : 0);
        result = 31 * result + (picture != null ? picture.hashCode() : 0);
        return result;
    }
}
