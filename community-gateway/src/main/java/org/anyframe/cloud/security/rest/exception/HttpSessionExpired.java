package org.anyframe.cloud.security.rest.exception;

/**
 * Created by Hahn on 2015-12-09.
 */
public class HttpSessionExpired extends RuntimeException{
    public HttpSessionExpired(String msg) {
        super(msg);
    }
}
