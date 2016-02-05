package org.anyframe.cloud.security.dto;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Created by Hahn on 2015-12-04.
 */
public class AnyframeUserDetails implements UserDetails, Serializable {

    private static final long serialVersionUID = 1413956276598270853l;

    private Collection<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();

    private UserAccountDto userAccountDto;

    public AnyframeUserDetails(UserAccountDto userAccountDto) {
        Assert.notNull(userAccountDto, "the provided userAccountDto reference can't be null");
        this.userAccountDto = userAccountDto;
        for (AuthorityDto authorityDto : userAccountDto.getAuthorities()) {
            this.grantedAuthorities.add(authorityDto);
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return userAccountDto.getPassword();
    }

    @Override
    public String getUsername() {
        return userAccountDto.getUserId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return isEnabled();
    }

    @Override
    public boolean isAccountNonLocked() {
        return isEnabled();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isEnabled();
    }

    @Override
    public boolean isEnabled() {
        return userAccountDto.isEnabled();
    }
}
