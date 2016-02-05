package org.anyframe;

import org.anyframe.notice.configuration.SwaggerConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@SpringBootApplication
@EnableRedisHttpSession
@EnableDiscoveryClient
@Import({ SwaggerConfiguration.class })
public class PortalNoticeApplication extends WebSecurityConfigurerAdapter{

    public static void main(String[] args) {
        SpringApplication.run(PortalNoticeApplication.class, args);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers(HttpMethod.GET, "/portal-notice/**")
        ;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.httpBasic()
                .and()
                .authorizeRequests()
                .anyRequest().hasRole("ADMIN")
//                .anyRequest().permitAll()
        ;
//        http
//                .httpBasic();
//                .and()
//                .authorizeRequests()
//                .antMatchers(HttpMethod.GET, "/portal-notice/**").permitAll()
//                .antMatchers(HttpMethod.POST, "/portal-notice/**").hasRole("ROLE_USER")
//                .antMatchers(HttpMethod.PUT, "/portal-notice/**").permitAll()
//                .anyRequest().authenticated();
    }
}
