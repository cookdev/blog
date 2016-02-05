package org.anyframe.cloud.user.application;

import org.anyframe.cloud.user.domain.RegisteredUser;

public interface RegistrationService {

	RegisteredUser registerNewUser(RegisteredUser newUser);

	RegisteredUser getUserById(String userId);

	RegisteredUser modifyUser(RegisteredUser registeredUser);

	void deleteUser(String userIdForDelete);

	void validatePassword(RegisteredUser registeredUser);

	RegisteredUser changePassword(RegisteredUser registeredUser, String existPassword);
}
