package org.anyframe.cloud.user.application;

import org.anyframe.cloud.user.domain.RegisteredUser;

public interface ApplicationEvents {

	void userRegistered(RegisteredUser registeredUser);
}
