
package org.anyframe.cloud.security.logout;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class LogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {
	
	@Value("${anyframe.logouturl}")
	private String logoutUrl;
	
	protected final Logger log = LoggerFactory.getLogger(this.getClass());
	
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
			
		log.debug("LogoutCall");
		super.setDefaultTargetUrl(logoutUrl);
		
		Cookie[] cookies = request.getCookies();
		
		if (null != cookies && cookies.length != 0) {
			
			for (Cookie cookie : cookies) {
				
				if (cookie.getName().contains("wordpress")) {
					
					log.debug("Old Cookie Detected with {} : {}", cookie.getName(), cookie.getValue());
					
					cookie.setMaxAge(0);
					response.addCookie(cookie);
					
				}
				
			}
			
		}
		
		super.onLogoutSuccess(request, response, authentication);
		
	}
	
}
