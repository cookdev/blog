
package org.anyframejava.search.model;

import java.util.Collections;
import java.util.List;

public class SearchResult {
	
	private long time = 0;
	private int totalCount = 0;
	private int count = 0;
	private int pageIndex = 1;
	private int pageSize = 10;
	
	private List<SearchDetail> result = Collections.emptyList();
	
	public long getTime() {
		
		return time;
		
	}
	
	public void setTime(long time) {
		
		this.time = time;
		
	}
	
	public int getTotalCount() {
		
		return totalCount;
		
	}
	
	public void setTotalCount(int totalCount) {
		
		this.totalCount = totalCount;
		
	}
	
	public int getCount() {
		
		return count;
		
	}
	
	public void setCount(int count) {
		
		this.count = count;
		
	}
	
	public int getPageIndex() {
		
		return pageIndex;
		
	}
	
	public void setPageIndex(int pageIndex) {
		
		this.pageIndex = pageIndex;
		
	}
	
	public int getPageSize() {
		
		return pageSize;
		
	}
	
	public void setPageSize(int pageSize) {
		
		this.pageSize = pageSize;
		
	}
	
	public List<SearchDetail> getResult() {
		
		return result;
		
	}
	
	public void setResult(List<SearchDetail> result) {
		
		this.result = result;
		
	}
	
}
