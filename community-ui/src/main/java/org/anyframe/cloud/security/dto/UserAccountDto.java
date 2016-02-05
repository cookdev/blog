package org.anyframe.cloud.security.dto;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by Hahn on 2015-12-04.
 */
public class UserAccountDto implements Serializable {

    private static final long serialVersionUID = 1413956276598270851l;

    private String userId;

    private String password;

    private boolean enabled;

    private Set<AuthorityDto> authorities = new HashSet<AuthorityDto>();

    public UserAccountDto(){}

    public String getUserId() { return userId; }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Set<AuthorityDto> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Set<AuthorityDto> authorities) {
        this.authorities = authorities;
    }
}
