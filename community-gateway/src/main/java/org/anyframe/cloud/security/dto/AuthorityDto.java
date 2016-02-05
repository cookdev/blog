package org.anyframe.cloud.security.dto;

import org.springframework.security.core.GrantedAuthority;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.io.Serializable;

/**
 * Created by Hahn on 2015-12-09.
 */
public class AuthorityDto implements GrantedAuthority, Serializable {

    private static final long serialVersionUID = 1413956276598270852l;

    private String authority;

    public AuthorityDto(){}

    public AuthorityDto(String authority) {
        this.authority = authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}
