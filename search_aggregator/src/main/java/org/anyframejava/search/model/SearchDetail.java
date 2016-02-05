
package org.anyframejava.search.model;

public class SearchDetail {
	
	private String location;
	private String title;
	private String contentType;
	private String summary;
	
	private SearchDetail() {
	}
	
	public SearchDetail(String location, String title, String contentType, String summary) {
		
		this.location = location;
		this.title = title;
		this.contentType = contentType;
		this.summary = summary;
		
	}
	
	public String getLocation() {
		
		return location;
		
	}
	
	public String getTitle() {
		
		return title;
		
	}
	
	public String getContentType() {
		
		return contentType;
		
	}
	
	public String getSummary() {
		
		return summary;
		
	}
	
}
