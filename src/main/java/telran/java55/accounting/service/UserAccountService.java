package telran.java55.accounting.service;

import telran.java55.accounting.dto.RolesDto;
import telran.java55.accounting.dto.UserDto;
import telran.java55.accounting.dto.UserEditDto;
import telran.java55.accounting.dto.UserRegisterDto;

public interface UserAccountService {

	UserDto register(UserRegisterDto userRegisterDto);

	UserDto removeUser(String login);

	UserDto getUser(String login);

	UserDto updateUser(String login, UserEditDto userEditDto);

	RolesDto changeRolesList(String login, String role, boolean isAddRole);

	void changePassword(String name, String newPassword);

}
