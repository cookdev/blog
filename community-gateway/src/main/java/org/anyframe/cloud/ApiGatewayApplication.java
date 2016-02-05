package org.anyframe.cloud;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.anyframe.cloud.gateway.config.SwaggerConfiguration;
import org.anyframe.cloud.security.logout.LogoutSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

@SpringBootApplication
@EnableZuulProxy
@EnableRedisHttpSession
@EnableDiscoveryClient
@ComponentScan(basePackages = "org.anyframe.cloud" )
@Import({ SwaggerConfiguration.class })
public class    ApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        @Autowired
        private UserDetailsService userDetailsService;
        
        @Autowired
        private LogoutSuccessHandler logoutSuccessHandler;

        @Autowired
        public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
            // @formatter:off

            auth
                    .userDetailsService(userDetailsService);
            auth.eraseCredentials(false);
//                    .passwordEncoder(passwordEncoder())
// @formatter:on
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring()
                    .antMatchers("/")
                    .antMatchers(HttpMethod.POST, "/user")
                    .antMatchers(HttpMethod.POST,"/security/register")
                    .antMatchers(HttpMethod.PUT,"/security/password")
                    .antMatchers(HttpMethod.DELETE,"/security/user/**")
                    .antMatchers("/**/*.{js,html}")
                    .antMatchers("/javascript/**/*.{js,html}")
                    .antMatchers("/bower_components/**")
                    .antMatchers("/i18n/**")
                    .antMatchers("/assets/**")
            ;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                    .httpBasic()
                    .and()
                        .logout()
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                        .logoutSuccessHandler(logoutSuccessHandler)
                    .and()
                    .csrf().csrfTokenRepository(csrfTokenRepository())
                    .and()
                    .addFilterAfter(csrfHeaderFilter(), SessionManagementFilter.class);
            // @formatter:on
        }

        private Filter csrfHeaderFilter() {
            return new OncePerRequestFilter() {
                @Override
                protected void doFilterInternal(HttpServletRequest request,
                                                HttpServletResponse response, FilterChain filterChain)
                        throws ServletException, IOException {
                    CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class
                            .getName());
                    if (csrf != null) {
                        Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
                        String token = csrf.getToken();
                        if (cookie == null || token != null
                                && !token.equals(cookie.getValue())) {
                            cookie = new Cookie("XSRF-TOKEN", token);
                            cookie.setPath("/");
                            response.addCookie(cookie);
                        }
                    }
                    filterChain.doFilter(request, response);
                }
            };
        }

        private CsrfTokenRepository csrfTokenRepository() {
            HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
            repository.setHeaderName("X-XSRF-TOKEN");
            return repository;
        }
    }
}
