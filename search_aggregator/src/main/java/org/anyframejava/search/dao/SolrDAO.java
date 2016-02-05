
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

@Repository("solrDAO")
public class SolrDAO {
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	private RestTemplate restTemplate;
	
	@Inject
	@Named("solrOptions")
	private Option solrOption;
	
	@Autowired
	private ObjectMapper objectMapper;
	
	@Value("${solr.url}")
	private String solrURL;
	
	@Value("${solr.path}")
	private String solrPath;
	
	@Value("${solr.id:}")
	private String solrId;
	
	@Value("${solr.pw:}")
	private String solrPW;
	
	public Map<String, Object> run(String query, int pageIndex, int pageSize) {
		
		Map<String, Object> result = new HashMap<String, Object>();
		
		int totalCount = 0;
		List<SearchDetail> searchDetailList = new ArrayList<SearchDetail>();
		
		Map<String, String> solrOptions = solrOption.getOptions();
		Set<String> keys = solrOptions.keySet();
		
		StringBuilder solrQueryURL = new StringBuilder(solrURL + solrPath);
		
		solrQueryURL.append("?q=" + query);
		solrQueryURL.append("&start=" + pageIndex * pageSize);
		solrQueryURL.append("&rows=" + pageSize);
		
		for (String key : keys) {
			
			solrQueryURL.append("&" + key + "=" + solrOptions.get(key));
			
		}
		
		log.debug(solrQueryURL.toString());
		
		try {
			
			ResponseEntity<String> responseEntity = restTemplate.exchange(solrQueryURL.toString(), HttpMethod.GET,
					setAuthorizationHeader(), String.class);
					
			JsonNode root = objectMapper.readTree(responseEntity.getBody());
			JsonNode response = root.path("response");
			
			totalCount = response.path("numFound").asInt();
			
			JsonNode docs = response.path("docs");
			JsonNode highlighting = root.path("highlighting");
			
			for (JsonNode doc : docs) {
				
				String id = doc.path("id").asText();
				
				String url = "";
				
				JsonNode urlNode = doc.path("url");
				Iterator<JsonNode> urlIterator = urlNode.iterator();
				
				if (urlIterator.hasNext()) {
					
					url = urlIterator.next().asText();
					
				}
				
				String title = "";
				
				JsonNode titleNode = doc.path("title");
				Iterator<JsonNode> titleIterator = titleNode.iterator();
				
				if (titleIterator.hasNext()) {
					
					title = titleIterator.next().asText();
					
				}
				
				String contentType = "";
				
				JsonNode contentTypeNode = doc.path("content_type");
				Iterator<JsonNode> contentTypeIterator = contentTypeNode.iterator();
				
				if (contentTypeIterator.hasNext()) {
					
					contentType = contentTypeIterator.next().asText();
					
					if (contentType.contains(";")) {
						
						contentType = contentType.split(";")[0];
						
					}
					
				}
				
				String summary = "";
				
				if (highlighting.has(id)) {
					
					JsonNode highlight = highlighting.path(id).path("content_kr");
					Iterator<JsonNode> highlightIterator = highlight.iterator();
					
					if (highlightIterator.hasNext()) {
						
						summary = highlightIterator.next().asText().replaceAll("\r\n|\r|\n|\t", " ");
						
					}
					
				}
				
				searchDetailList.add(new SearchDetail(url, title, contentType, summary));
				
			}
			
		} catch (Exception e) {
			
			e.printStackTrace();
			
		}
		
		result.put("totalCount", totalCount);
		result.put("searchDetailList", searchDetailList);
		
		return result;
		
	}
	
	private HttpEntity<?> setAuthorizationHeader() {
		
		if ("".equals(solrId) || "".equals(solrPW)) return null;
		
		String solrCredential = solrId + ":" + solrPW;
		
		String solrEncodedCredential = new String(Base64.encodeBase64(solrCredential.getBytes()));
		
		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", "Basic " + solrEncodedCredential);
		
		return new HttpEntity<String>(headers);
		
	}
	
}
