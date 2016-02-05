
package org.anyframejava.search.dao;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.anyframejava.search.config.SearchApplicationConfiguration.Option;
import org.anyframejava.search.model.SearchDetail;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Repository("blogDAO")
public class BlogDAO {
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	private RestTemplate restTemplate;
	
	// @Inject
	// @Named("blogOptions")
	// private Option blogOption;
	
	@Autowired
	private ObjectMapper objectMapper;
	
	@Value("${blog.url}")
	private String blogURL;
	
	@Value("${blog.path}")
	private String blogPath;
	
	@Value("${solr.options.hl.fragsize}")
	private int fragSize;
	
	@Value("${solr.options.hl.simple.pre}")
	private String prefix;
	
	@Value("${solr.options.hl.simple.post}")
	private String postfix;
	
	public Map<String, Object> run(String query, int pageIndex, int pageSize) {
		
		Map<String, Object> result = new HashMap<String, Object>();
		
		int totalCount = 0;
		List<SearchDetail> searchDetailList = new ArrayList<SearchDetail>();
		
		// Map<String, String> blogOptions = blogOption.getOptions();
		// Set<String> keys = blogOptions.keySet();
		
		StringBuilder blogQueryURL = new StringBuilder(blogURL + blogPath);
		
		blogQueryURL.append("?search=" + query);
		blogQueryURL.append("&page=" + pageIndex);
		blogQueryURL.append("&count=" + pageSize);
		
		// for (String key : keys) {
		//
		// blogQueryURL.append("&" + key + "=" + blogOptions.get(key));
		//
		// }
		
		log.debug(blogQueryURL.toString());
		
		try {
			
			ResponseEntity<String> response = restTemplate.exchange(blogQueryURL.toString(), HttpMethod.GET, null,
					String.class);
					
			JsonNode root = objectMapper.readTree(response.getBody());
			
			JsonNode posts = root.path("posts");
			
			totalCount = root.path("count_total").asInt();
			
			for (JsonNode post : posts) {
				
				String url = post.path("url").asText();
				
				String title = post.path("title").asText();
				
				String contentType = "text/html";
				
				// String summary = Jsoup.parse(post.path("content").asText()).text();
				// String summary = post.path("content").asText();
				String summary = summarizeContent(Jsoup.parse(post.path("content").asText()).text(), query);
				
				log.debug(summary);
				
				searchDetailList.add(new SearchDetail(url, title, contentType, summary));
				
			}
			
		} catch (Exception e) {
			
			e.printStackTrace();
			
		}
		
		result.put("totalCount", totalCount);
		result.put("searchDetailList", searchDetailList);
		
		return result;
		
	}
	
	private String summarizeContent(String content, String query) {
		
		if (fragSize > content.length()) {
			
			return content.replaceAll(query, prefix + query + postfix).replaceAll("\r\n|\r|\n|\t", " ");
			
		}
		
		StringBuilder contentBuilder = new StringBuilder(content);
		
		int contentLength = contentBuilder.length();
		
		int queryIndex = contentBuilder.indexOf(query);
		
		if (queryIndex < (fragSize / 2)) {
			
			return contentBuilder.substring(0, fragSize).replaceAll(query, prefix + query + postfix)
					.replaceAll("\r\n|\r|\n|\t", " ");
					
		} else if (queryIndex > (contentLength - (fragSize / 2))) {
			
			return contentBuilder.substring(contentLength - 300, contentLength - 1)
					.replaceAll(query, prefix + query + postfix).replaceAll("\r\n|\r|\n|\t", " ");
					
		}
		
		return contentBuilder.substring(queryIndex - 150, queryIndex + 150).replaceAll(query, prefix + query + postfix)
				.replaceAll("\r\n|\r|\n|\t", " ");
				
	}
	
}
