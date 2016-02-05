package org.anyframe.cloud.user.interfaces.facade.dto;


public class UserAccountRequest {
	
	private String id;
	
	private String emailAddress;
	
	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getEmailAddress() {
		return emailAddress;
	}
	
	public void setEmailAddress(String emailAddress) {
		this.emailAddress = emailAddress;
	}

}
