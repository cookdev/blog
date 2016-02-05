package org.anyframe.cloud.ui;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import org.anyframe.cloud.ui.config.SwaggerConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
@EnableRedisHttpSession
@EnableDiscoveryClient
@Import({ SwaggerConfiguration.class })
public class CommunityUiApplication extends WebSecurityConfigurerAdapter {

    @RequestMapping("/user")
    public Map<String, String> user(Principal user) {
        return Collections.singletonMap("name", user.getName());
    }

    public static void main(String[] args) {
        SpringApplication.run(CommunityUiApplication.class, args);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/")
                .antMatchers("/**/*.{js,html}")
                .antMatchers("/javascript/**/*.{js,html}")
                .antMatchers("/bower_components/**")
                .antMatchers("/i18n/**")
                .antMatchers("/assets/**")
        ;
    }
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic()
                .and()
				.authorizeRequests()
//					.antMatchers("/index.html", "/login", "/", "/**/*.{js,html,css}").anonymous()
//                .anyRequest().authenticated();
                .anyRequest().anonymous();
    }

//
//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http
//                .logout()
//                .and()
//
//                .antMatcher("/**").authorizeRequests()
//                .antMatchers("/index.html", "/").permitAll()
//                .anyRequest().authenticated()
//                .and()
//
//                .csrf()
//                .csrfTokenRepository(csrfTokenRepository())
//                .and()
//
//                .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);
//    }
//
//    private Filter csrfHeaderFilter() {
//        return new OncePerRequestFilter() {
//            @Override
//            protected void doFilterInternal(HttpServletRequest request,
//                                            HttpServletResponse response, FilterChain filterChain)
//                    throws ServletException, IOException {
//                CsrfToken csrf = (CsrfToken) request
//                        .getAttribute(CsrfToken.class.getName());
//                if (csrf != null) {
//                    Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
//                    String token = csrf.getToken();
//                    if (cookie == null
//                            || token != null && !token.equals(cookie.getValue())) {
//                        cookie = new Cookie("XSRF-TOKEN", token);
//                        cookie.setPath("/");
//                        response.addCookie(cookie);
//                    }
//                }
//                filterChain.doFilter(request, response);
//            }
//        };
//    }
//
//    private CsrfTokenRepository csrfTokenRepository() {
//        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
//        repository.setHeaderName("X-XSRF-TOKEN");
//        return repository;
//    }
//}
//
//// Remove this when upgrading to Spring Boot 1.3.1 (https://github.com/spring-projects/spring-boot/issues/4553)
//@Component
//@Order(Ordered.HIGHEST_PRECEDENCE)
//class WorkaroundRestTemplateCustomizer implements UserInfoRestTemplateCustomizer {
//
//    @Override
//    public void customize(OAuth2RestTemplate template) {
//        template.setInterceptors(new ArrayList<>(template.getInterceptors()));
//    }

}
