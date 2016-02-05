
package org.anyframe.cloud.ui.sso.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class GenerateAuthCookie {
	
	private String cookie;
	
	@JsonProperty("cookie_name")
	private String cookieName;
	
	public String getCookie() {
		
		return cookie;
		
	}
	
	public void setCookie(String cookie) {
		
		this.cookie = cookie;
		
	}
	
	public String getCookieName() {
		
		return cookieName;
		
	}
	
	public void setCookieName(String cookieName) {
		
		this.cookieName = cookieName;
		
	}
	
	@Override
	public String toString() {
		
		return "GenerateAuthCookie [cookie=" + cookie + ", cookieName=" + cookieName + "]";
		
	}
	
}
