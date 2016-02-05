package org.anyframe.cloud.user;

import com.google.common.base.Predicate;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.service.ApiInfo;

import static springfox.documentation.builders.PathSelectors.regex;

@SpringBootApplication
@EnableRedisHttpSession
@EnableDiscoveryClient
public class CommunityUserApplication extends WebSecurityConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(CommunityUserApplication.class, args);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers(HttpMethod.GET, "/user/**")
                .antMatchers(HttpMethod.POST, "/user")
        ;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/user/**").permitAll()
                .antMatchers(HttpMethod.PUT, "/user/**").permitAll()
//                .antMatchers("/user/**").anonymous()
                .anyRequest().authenticated();
    }

    @Bean
    public Predicate<String> swaggerPaths() {
        return regex("/user.*|/sign.*|/log.*|/withdrawal.*|/cargo.*");
    }

    @Bean
    public ApiInfo apiInfo() {
        return new ApiInfoBuilder().title("User API")
                .description("User API")
                .contact("Anyframe Cloud Edition")
                .license("Anyframe Cloud Ed.").version("1.0").build();
    }
}
