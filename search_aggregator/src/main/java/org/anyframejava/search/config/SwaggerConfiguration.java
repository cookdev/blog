
package org.anyframejava.search.config;

import static springfox.documentation.builders.PathSelectors.regex;

import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.base.Predicate;

import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.schema.configuration.ObjectMapperConfigured;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfiguration {
	
	@Bean
	public Docket swaggerSpringMvcPlugin(Predicate<String> pathPredicate, ApiInfo apiInfo) {
		
		return new Docket(DocumentationType.SWAGGER_2).apiInfo(apiInfo).select().paths(pathPredicate).build();
	}
	
	@Bean
	public ApplicationListener<ObjectMapperConfigured> configuredApplicationListener() {
		
		return new ApplicationListener<ObjectMapperConfigured>() {
			
			@Override
			public void onApplicationEvent(ObjectMapperConfigured event) {
				
				ObjectMapper om = event.getObjectMapper();
				om.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
				om.setVisibilityChecker(om.getSerializationConfig().getDefaultVisibilityChecker()
						.withFieldVisibility(JsonAutoDetect.Visibility.ANY)
						.withGetterVisibility(JsonAutoDetect.Visibility.NONE)
						.withSetterVisibility(JsonAutoDetect.Visibility.NONE));
						
			}
		};
	}
	
	@Bean
	public Predicate<String> swaggerPaths() {
		
		return regex("/search.*");
		
	}
	
	@Bean
	public ApiInfo apiInfo() {
		
		return new ApiInfoBuilder().title("SSC Search API").description("SSC Search API").contact("SSC").license("SSC")
				.version("1.0").build();
				
	}
	
}
