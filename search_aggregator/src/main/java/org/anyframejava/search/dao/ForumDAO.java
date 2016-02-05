
package org.anyframejava.search.dao;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.anyframejava.search.config.SearchApplicationConfiguration.Option;
import org.anyframejava.search.model.SearchDetail;
import org.apache.tomcat.util.codec.binary.Base64;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Repository("forumDAO")
public class ForumDAO {
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	private RestTemplate restTemplate;
	
	// @Inject
	// @Named("forumOptions")
	// private Option forumOption;
	
	@Autowired
	private ObjectMapper objectMapper;
	
	@Value("${forum.url}")
	private String forumURL;
	
	@Value("${forum.path}")
	private String forumPath;
	
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
		
		// Map<String, String> forumOptions = forumOption.getOptions();
		// Set<String> keys = forumOptions.keySet();
		
		StringBuilder forumQueryURL = new StringBuilder(forumURL + forumPath);
		
		forumQueryURL.append("?search=" + query);
		forumQueryURL.append("&page=" + pageIndex);
		forumQueryURL.append("&count=" + pageSize);
		
		// for (String key : keys) {
		//
		// forumQueryURL.append("&" + key + "=" + forumOptions.get(key));
		//
		// }
		
		log.debug(forumQueryURL.toString());
		
		try {
			
			ResponseEntity<String> response = restTemplate.exchange(forumQueryURL.toString(), HttpMethod.GET, null,
					String.class);
					
			JsonNode root = objectMapper.readTree(response.getBody());
			
			JsonNode posts = root.path("posts");
			
			totalCount = root.path("count_total").asInt();
			
			for (JsonNode post : posts) {
				
				String url = post.path("url").asText();
				
				String title = post.path("title").asText();
				
				String contentType = "text/html";
				
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
