
package org.anyframe.cloud.security.rest;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.anyframe.cloud.security.dto.AnyframeUserDetails;
import org.anyframe.cloud.security.rest.exception.HttpSessionExpired;
import org.anyframe.cloud.sso.wordpress.model.GenerateAuthCookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Created by Hahn on 2015-12-04.
 */
@RestController
public class UserAuthenticationController {
	
	@Value("${anyframe.forum.url}")
	private String forumUrl;
	
	@Value("${anyframe.forum.path}")
	private String forumPath;
	
	@Value("${anyframe.forum.params}")
	private String[] forumParams;
	
	@Value("${anyframe.blog.url}")
	private String blogUrl;
	
	@Value("${anyframe.blog.path}")
	private String blogPath;
	
	@Value("${anyframe.blog.params}")
	private String[] blogParams;
	
	private RestTemplate restTemplate = new RestTemplate();
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	
	@RequestMapping("/hello")
	public Map<String, Object> user(Principal user, HttpServletResponse response) {
		
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		map.put("name", user.getName());
		map.put("roles", AuthorityUtils.authorityListToSet(((Authentication) user).getAuthorities()));
		
		StringBuilder blogURI = new StringBuilder(blogUrl).append(blogPath).append("?").append(blogParams[0])
				.append("=").append(user.getName()).append("&").append(blogParams[1]).append("=")
				.append(((Authentication) user).getCredentials());
				
		log.info(blogURI.toString());
		
		GenerateAuthCookie blogAuthCookie = restTemplate.getForObject(blogURI.toString(), GenerateAuthCookie.class);
		
		log.info(blogAuthCookie.toString());
		
		Cookie blogCookie = new Cookie(blogAuthCookie.getCookieName(), blogAuthCookie.getCookie());
		
		blogCookie.setDomain(".ssc.com");
		blogCookie.setPath("/");
		blogCookie.setMaxAge(-1);
		blogCookie.setHttpOnly(true);
		blogCookie.setSecure(true);
		
		response.addCookie(blogCookie);
		
		StringBuilder forumURI = new StringBuilder(forumUrl).append(forumPath).append("?").append(forumParams[0])
				.append("=").append(user.getName()).append("&").append(forumParams[1]).append("=")
				.append(((Authentication) user).getCredentials());

		log.info(forumURI.toString());

		GenerateAuthCookie forumAuthCookie = restTemplate.getForObject(forumURI.toString(), GenerateAuthCookie.class);

		log.info(forumAuthCookie.toString());

		Cookie forumCookie = new Cookie(forumAuthCookie.getCookieName(), forumAuthCookie.getCookie());

		forumCookie.setDomain(".ssc.com");
		forumCookie.setPath("/");
		forumCookie.setMaxAge(-1);
		forumCookie.setHttpOnly(true);
		forumCookie.setSecure(true);

		response.addCookie(forumCookie);
		
		return map;
		
	}
	
	@RequestMapping("/who-am-i")
	public Map<String, Object> whoAmI(Authentication authentication) {

		if (authentication == null) {

			throw new HttpSessionExpired("Http Session Expired.");

		}
		
		AnyframeUserDetails userDetails = (AnyframeUserDetails) authentication.getPrincipal();
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		
		map.put("name", userDetails.getUsername());
		map.put("roles", AuthorityUtils.authorityListToSet((userDetails.getAuthorities())));
		
		return map;
		
	}
	
	@ResponseStatus(value = HttpStatus.GONE, reason = "Http Session Expired.")
	@ExceptionHandler(HttpSessionExpired.class)
	public void httpSessionExpiredException() {
	
	}
	
}
