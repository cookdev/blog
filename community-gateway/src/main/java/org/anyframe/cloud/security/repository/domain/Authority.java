package org.anyframe.cloud.security.repository.domain;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.io.Serializable;

/**
 * Created by Hahn on 2015-12-09.
 */
@Entity
public class Authority implements Serializable {

    @Id
    private String authority;

    public Authority() {}

    public Authority(String authority) {
        this.authority = authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public String getAuthority() {
        return authority;
    }
}
