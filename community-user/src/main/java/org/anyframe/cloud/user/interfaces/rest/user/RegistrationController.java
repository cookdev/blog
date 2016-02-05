package org.anyframe.cloud.user.interfaces.rest.user;

import java.nio.charset.Charset;

import javax.servlet.http.HttpServletRequest;

import org.anyframe.cloud.security.dto.UserAccountDto;
import org.anyframe.cloud.user.application.RegistrationService;
import org.anyframe.cloud.user.application.exception.IDAlreadyExistException;
import org.anyframe.cloud.user.application.exception.PasswordIsWrongException;
import org.anyframe.cloud.user.application.exception.UserIsNotExistException;
import org.anyframe.cloud.user.domain.RegisteredUser;
import org.anyframe.cloud.user.interfaces.facade.dto.PasswordChangeDTO;
import org.anyframe.cloud.user.interfaces.facade.dto.PasswordValidationDTO;
import org.anyframe.cloud.user.interfaces.facade.dto.UserInfoDTO;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@RestController
public class RegistrationController {
	
    private static final Logger logger = LoggerFactory.getLogger(RegistrationController.class);

	@Autowired
	private RegistrationService registrationService;
	
	@Value("${community.security.registerUrl}")
	private String gatewayRegisterUrl;
	
	@Value("${community.security.passwordResetUrl}")
	private String gatewayPasswordUrl;
	
	@Value("${community.security.userUrl}")
	private String gatewayUserUrl;

	private RestTemplate restTemplate = new RestTemplate();
    
    @RequestMapping(value = {"/user"}, method = {RequestMethod.POST})
    @ResponseStatus(HttpStatus.CREATED)
    public RegisteredUser registerUser(@RequestBody RegisteredUser newUser, HttpServletRequest request) throws Exception{

        HttpHeaders securityHeaders = new HttpHeaders();
        securityHeaders.set("X-XSRF-TOKEN", request.getHeader("X-XSRF-TOKEN"));
        securityHeaders.set("Content-type", "application/json");

        UserAccountDto userAccount = new UserAccountDto();
        userAccount.setUserId(newUser.getUserId());
        userAccount.setPassword(newUser.getPassword());
        userAccount.setEnabled(true);

        HttpEntity securityEntity = new HttpEntity(userAccount, securityHeaders);

        ResponseEntity<String> securityExchange = restTemplate.exchange(
        		gatewayRegisterUrl,
                HttpMethod.POST,
                securityEntity,
                String.class);


        // Nonce 호출
        String url = "https://forum.ssc.com/api/core/get_nonce?controller=user&method=register";

        ResponseEntity<String> exchange = restTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                String.class);
        
        // exchange Body에서 nonce 가져오기
        JSONParser parser = new JSONParser();
        JSONObject jsonObj = (JSONObject)parser.parse(exchange.getBody().toString());
        String nonce = jsonObj.get("nonce").toString();

        // urlencoded 방식 변경 및 한글 처리
    	HttpHeaders headers = new HttpHeaders();
        Charset utf8 = Charset.forName("UTF-8");
        MediaType mediaType = new MediaType("application", "x-www-form-urlencoded", utf8);
        headers.setContentType(mediaType);
        
        // User 정보 Setting
        String formdata = "username=" + newUser.getUserId() + "&user_pass=" + newUser.getPassword() + "&email=" + newUser.getEmail() + "&nonce=" + nonce + "&display_name=" + newUser.getUserName();
        HttpEntity entity = new HttpEntity(formdata, headers);

        if(!exchange.getBody().isEmpty()){
            // 토큰을 성공적으로 받아온 경우
        	String registerUrl = "https://forum.ssc.com/api/user/register";

            try{
                // Forum에 User 등록 성공
	        	ResponseEntity<String> forumResult = restTemplate.exchange(
	        			registerUrl,
	                    HttpMethod.POST,
	                    entity,
	                    String.class
	        	);
        	} catch(HttpStatusCodeException e){
                // Forum에 User 등록 실패
        		String errorpayload = e.getResponseBodyAsString();
        		
        		JSONObject errorObj = (JSONObject)parser.parse(errorpayload);
                String errorMessage = errorObj.get("error").toString();
                
                if(("Username already exists").equals(errorMessage)){
                    // 기존 ID가 존재하는 경우
                	throw new Exception("ID is Already existed");
                }
        	} catch(RestClientException e){
        		throw new Exception(e.getMessage());
        	}
        }else{
            // 토큰 가져오기 실패한 경우
            throw new Exception("Nonce Error");
        }

        // Potal에 User 등록
        RegisteredUser registeredUser = registrationService.registerNewUser(newUser);

        return registeredUser;
    }

    @RequestMapping(value = {"/user/{userIdForModify}"}, method = {RequestMethod.PUT})
    @ResponseStatus(HttpStatus.OK)
    public RegisteredUser modifyUser(@RequestBody RegisteredUser registeredUser, @PathVariable String userIdForModify) throws Exception{
    	
    	// password를 화면상에서 전달하지 못하므로 DB에서 조회
    	RegisteredUser registeredUserPassword = registrationService.getUserById(registeredUser.getUserId());
    	
    	// cookie 호출
    	String url = "https://forum.ssc.com/api/user/generate_auth_cookie";

    	// urlencoded 방식 변경 및 한글 처리
    	HttpHeaders headers = new HttpHeaders();
        Charset utf8 = Charset.forName("UTF-8");
        MediaType mediaType = new MediaType("application", "x-www-form-urlencoded", utf8);
        headers.setContentType(mediaType);
        
        // Password 정보 Setting
        String userdata = "username=" + registeredUser.getUserId() + "&password=" + registeredUserPassword.getPassword();
        HttpEntity userEntity = new HttpEntity(userdata, headers);
        
    	ResponseEntity<String> exchange = restTemplate.exchange(
   			    url,
                HttpMethod.POST,
                userEntity,
                String.class);
    	
    	// exchange Body에서 cookie 가져오기
        JSONParser parser = new JSONParser();
        JSONObject jsonObj = (JSONObject)parser.parse(exchange.getBody().toString());
        String cookie = jsonObj.get("cookie").toString();
        
        // exchange Body에서 userId(id) 가져오기
        JSONObject userObj = (JSONObject)parser.parse(jsonObj.get("user").toString());
        String wordpressUserId = userObj.get("id").toString();
        
        if(!exchange.getBody().isEmpty()){
        	String passwordModifyUrl = "https://forum.ssc.com/api/changeuser/update_user_profile";

            // 사용자 정보 Setting
            String formdata = "user_id=" + wordpressUserId + "&display_name=" + registeredUser.getUserName() + "&email=" + registeredUser.getEmail() + "&cookie=" + cookie;
            HttpEntity entity = new HttpEntity(formdata, headers);
            
            try{
                // Forum에 User 정보 변경 성공
	        	ResponseEntity<String> forumResult = restTemplate.exchange(
	        			passwordModifyUrl,
	                    HttpMethod.POST,
	                    entity,
	                    String.class
	        	);
        	} catch(HttpStatusCodeException e){
                // Forum에 User 정보 변경 실패
        		String errorpayload = e.getResponseBodyAsString();
        		
        		JSONObject errorObj = (JSONObject)parser.parse(errorpayload);
                String errorMessage = errorObj.get("error").toString();
               
                throw new Exception(errorMessage);
        	
        	} catch(RestClientException e){
        		throw new Exception(e.getMessage());
        	}
        	
        }else{
            // 토큰 가져오기 실패한 경우
            throw new Exception("Nonce Error");
        }
        
        logger.debug("##### User ID for modify : {}", userIdForModify);
        if(registeredUser.getUserId() == null){
            registeredUser.setUserId(userIdForModify);
        }

        RegisteredUser modifiedUser = registrationService.modifyUser(registeredUser);
        return modifiedUser;
    }

    @RequestMapping(value = {"/user/{userIdForDelete}"}, method = {RequestMethod.DELETE})
    @ResponseStatus(HttpStatus.OK)
    public void deleteUser(@PathVariable String userIdForDelete, HttpServletRequest request) throws Exception{

    	// Security
        HttpHeaders securityHeaders = new HttpHeaders();
        securityHeaders.set("X-XSRF-TOKEN", request.getHeader("X-XSRF-TOKEN"));
        securityHeaders.set("Content-type", "application/json");

        UserAccountDto userAccount = new UserAccountDto();
        userAccount.setUserId(userIdForDelete);

        HttpEntity securityEntity = new HttpEntity(userAccount, securityHeaders);

        restTemplate.delete(gatewayUserUrl+"/"+userIdForDelete);
    	
    	
    	// password를 화면상에서 전달하지못하므로 DB에서 조회
    	RegisteredUser registeredUserPassword = registrationService.getUserById(userIdForDelete);
    	
    	// cookie 호출
    	String url = "https://forum.ssc.com/api/user/generate_auth_cookie";
    	
    	// urlencoded 방식 변경 및 한글 처리
    	HttpHeaders headers = new HttpHeaders();
        Charset utf8 = Charset.forName("UTF-8");
        MediaType mediaType = new MediaType("application", "x-www-form-urlencoded", utf8);
        headers.setContentType(mediaType);
        
        // User 정보 Setting
        String userdata = "username=" + userIdForDelete + "&password=" + registeredUserPassword.getPassword();
        HttpEntity userEntity = new HttpEntity(userdata, headers);
        
    	ResponseEntity<String> exchange = restTemplate.exchange(
   			    url,
                HttpMethod.POST,
                userEntity,
                String.class);
    	
    	// exchange Body에서 cookie 가져오기
        JSONParser parser = new JSONParser();
        JSONObject jsonObj = (JSONObject)parser.parse(exchange.getBody().toString());
        String cookie = jsonObj.get("cookie").toString();
        
        // exchange Body에서 userId(id) 가져오기
        JSONObject userObj = (JSONObject)parser.parse(jsonObj.get("user").toString());
        String wordpressUserId = userObj.get("id").toString();
        
        if(!exchange.getBody().isEmpty()){
        	String passwordModifyUrl = "https://forum.ssc.com/api/changeuser/remove_user";

            // 사용자 정보 Setting
            String modifydata = "user_id=" + wordpressUserId + "&cookie=" + cookie;
            HttpEntity modifyEntity = new HttpEntity(modifydata, headers);
            
            try{
                // Forum에 User 삭제 성공
	        	ResponseEntity<String> forumResult = restTemplate.exchange(
	        			passwordModifyUrl,
	                    HttpMethod.POST,
	                    modifyEntity,
	                    String.class
	        	);
        	} catch(HttpStatusCodeException e){
                // Forum에 User 삭제 실패
        		String errorpayload = e.getResponseBodyAsString();
        		
        		JSONObject errorObj = (JSONObject)parser.parse(errorpayload);
                String errorMessage = errorObj.get("error").toString();
                
                throw new Exception(errorMessage);
                
        	} catch(RestClientException e){
        		throw new Exception(e.getMessage());
        	}
        }else{
            // 토큰 가져오기 실패한 경우
            throw new Exception("Nonce Error");
        }
        
        logger.debug("##### User ID for delete : {}", userIdForDelete);
        registrationService.deleteUser(userIdForDelete);
    }

    @RequestMapping(value = {"/user/{userId}"}, method = {RequestMethod.GET})
    @ResponseStatus(HttpStatus.OK)
    public UserInfoDTO getUser(@PathVariable String userId){
        UserInfoDTO resultUserInfo = new UserInfoDTO();

        logger.info("##### User ID for inquiry : {}", userId);
        RegisteredUser registeredUser =  registrationService.getUserById(userId);

        resultUserInfo.setUserId(registeredUser.getUserId());
        resultUserInfo.setUserName(registeredUser.getUserName());
        resultUserInfo.setEmail(registeredUser.getEmail());
        resultUserInfo.setPicture(registeredUser.getPicture());

        return resultUserInfo;
    }

    @RequestMapping(value = {"/user/password/validation"}, method = {RequestMethod.POST})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void validatePassword(@RequestBody PasswordValidationDTO passwordValidationDTO){

        RegisteredUser registeredUser = new RegisteredUser();
        registeredUser.setUserId(passwordValidationDTO.getUserId());
        registeredUser.setPassword(passwordValidationDTO.getPassword());

        registrationService.validatePassword(registeredUser);
    }

    @RequestMapping(value = {"/user/password/change"}, method = {RequestMethod.PUT})
    @ResponseStatus(HttpStatus.OK)
    public RegisteredUser changePassword(@RequestBody PasswordChangeDTO passwordChangeDTO, HttpServletRequest request) throws Exception{
    	
    	// Security
        HttpHeaders securityHeaders = new HttpHeaders();
        securityHeaders.set("X-XSRF-TOKEN", request.getHeader("X-XSRF-TOKEN"));
        securityHeaders.set("Content-type", "application/json");

        UserAccountDto userAccount = new UserAccountDto();
        userAccount.setUserId(passwordChangeDTO.getUserId());
        userAccount.setPassword(passwordChangeDTO.getPassword());

        HttpEntity securityEntity = new HttpEntity(userAccount, securityHeaders);

        ResponseEntity<String> securityExchange = restTemplate.exchange(
        		gatewayPasswordUrl,
                HttpMethod.PUT,
                securityEntity,
                String.class);
    	
    	// cookie 호출
    	String url = "https://forum.ssc.com/api/user/generate_auth_cookie";
    	
    	// urlencoded 방식 변경 및 한글 처리
    	HttpHeaders headers = new HttpHeaders();
        Charset utf8 = Charset.forName("UTF-8");
        MediaType mediaType = new MediaType("application", "x-www-form-urlencoded", utf8);
        headers.setContentType(mediaType);
        
        // Password 정보 Setting
        String userdata = "username=" + passwordChangeDTO.getUserId() + "&password=" + passwordChangeDTO.getExistPassword();
        HttpEntity userEntity = new HttpEntity(userdata, headers);
        
    	ResponseEntity<String> exchange = restTemplate.exchange(
   			    url,
                HttpMethod.POST,
                userEntity,
                String.class);
    	
    	// exchange Body에서 cookie 가져오기
        JSONParser parser = new JSONParser();
        JSONObject jsonObj = (JSONObject)parser.parse(exchange.getBody().toString());
        String status = jsonObj.get("status").toString();
        
        if(("error").equals(status)){
        	String nonceErrorMessage = jsonObj.get("error").toString();
        	throw new Exception(nonceErrorMessage);
        }
        
        String cookie = jsonObj.get("cookie").toString();
        
        // exchange Body에서 userId(id) 가져오기
        JSONObject userObj = (JSONObject)parser.parse(jsonObj.get("user").toString());
        String wordpressUserId = userObj.get("id").toString();
        
        if(!exchange.getBody().isEmpty()){
        	String passwordModifyUrl = "https://forum.ssc.com/api/changeuser/update_user_password";

            // Password 정보 Setting
            String modifydata = "user_id=" + wordpressUserId + "&old_user_pass=" + passwordChangeDTO.getExistPassword() + "&user_pass=" + passwordChangeDTO.getPassword() + "&cookie=" + cookie;
            HttpEntity modifyEntity = new HttpEntity(modifydata, headers);
            
            try{
                // Forum에 Password 변경 성공
	        	ResponseEntity<String> forumResult = restTemplate.exchange(
	        			passwordModifyUrl,
	                    HttpMethod.POST,
	                    modifyEntity,
	                    String.class
	        	);
        	} catch(HttpStatusCodeException e){
                // Forum에 Password 변경 실패
        		String errorpayload = e.getResponseBodyAsString();
        		
        		JSONObject errorObj = (JSONObject)parser.parse(errorpayload);
                String errorMessage = errorObj.get("error").toString();
                
                throw new Exception(errorMessage);
                
        	} catch(RestClientException e){
        		throw new Exception(e.getMessage());
        	}
        	
        }else{
            // 토큰 가져오기 실패한 경우
            throw new Exception("Nonce Error");
        }
    	
        RegisteredUser registeredUser = new RegisteredUser();
        registeredUser.setUserId(passwordChangeDTO.getUserId());
        registeredUser.setPassword(passwordChangeDTO.getPassword());

        RegisteredUser modifiedUser = registrationService.changePassword(registeredUser, passwordChangeDTO.getExistPassword());

        return modifiedUser;
    }

    @ResponseStatus(value = HttpStatus.CONFLICT, reason = "ID is Already existed")
    @ExceptionHandler(IDAlreadyExistException.class)
    public void idAlreadyExistException(){
    }

    @ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "User Is Not Found")
    @ExceptionHandler(UserIsNotExistException.class)
    public void userIsNotExistException(){
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Password Is Wrong")
    @ExceptionHandler(PasswordIsWrongException.class)
    public void passwordIsWrongException(){
    }
   
}
