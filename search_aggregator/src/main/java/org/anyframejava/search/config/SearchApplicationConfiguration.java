
package org.anyframejava.search.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class SearchApplicationConfiguration {
	
	@Bean
	public RestTemplate restTemplate() {
		
		return new RestTemplate();
		
	}
	
	@Bean
	@ConfigurationProperties("solr")
	public Option solrOptions() {
		
		return new Option();
		
	}
	
	// @Bean
	// @ConfigurationProperties("forum")
	// public Option forumOptions() {
	//
	// return new Option();
	//
	// }
	//
	// @Bean
	// @ConfigurationProperties("blog")
	// public Option blogOptions() {
	//
	// return new Option();
	//
	// }
	
	public static class Option {
		
		private Map<String, String> options = new HashMap<String, String>();
		
		public Map<String, String> getOptions() {
			
			return this.options;
			
		}
		
	}
	
}
