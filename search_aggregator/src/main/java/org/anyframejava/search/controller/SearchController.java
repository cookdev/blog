
package org.anyframejava.search.controller;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.anyframejava.search.dao.BlogDAO;
import org.anyframejava.search.dao.ForumDAO;
import org.anyframejava.search.dao.SolrDAO;
import org.anyframejava.search.model.SearchDetail;
import org.anyframejava.search.model.SearchResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/search")
public class SearchController {
	
	@Autowired
	private SolrDAO solrDAO;
	
	@Autowired
	private ForumDAO forumDAO;
	
	@Autowired
	private BlogDAO blogDAO;
	
	@RequestMapping(value = "/solr", method = RequestMethod.GET)
	private @ResponseBody SearchResult searchSolr(@RequestParam String query,
			@RequestParam(defaultValue = "1") int pageIndex, @RequestParam(defaultValue = "10") int pageSize) {
			
		long startTime = System.nanoTime();
		
		SearchResult searchResult = new SearchResult();
		
		Map<String, Object> searchDetail = solrDAO.run(query, pageIndex - 1, pageSize);
		
		int totalCount = (Integer) searchDetail.get("totalCount");
		List<SearchDetail> solrSearchDetail = (List<SearchDetail>) searchDetail.get("searchDetailList");
		
		searchResult.setCount(solrSearchDetail.size());
		searchResult.setResult(solrSearchDetail);
		searchResult.setPageIndex(pageIndex);
		searchResult.setPageSize(pageSize);
		searchResult.setTotalCount(totalCount);
		
		long endTime = System.nanoTime();
		
		long duration = endTime - startTime;
		
		searchResult.setTime(TimeUnit.MILLISECONDS.convert(duration, TimeUnit.NANOSECONDS));
		
		return searchResult;
		
	}
	
	@RequestMapping(value = "/blog", method = RequestMethod.GET)
	private @ResponseBody SearchResult searchBlog(@RequestParam String query,
			@RequestParam(defaultValue = "1") int pageIndex, @RequestParam(defaultValue = "10") int pageSize) {
			
		long startTime = System.nanoTime();
		
		SearchResult searchResult = new SearchResult();
		
		Map<String, Object> searchDetail = blogDAO.run(query, pageIndex, pageSize);
		
		int totalCount = (Integer) searchDetail.get("totalCount");
		List<SearchDetail> blogSearchDetail = (List<SearchDetail>) searchDetail.get("searchDetailList");
		
		searchResult.setCount(blogSearchDetail.size());
		searchResult.setResult(blogSearchDetail);
		searchResult.setPageIndex(pageIndex);
		searchResult.setPageSize(pageSize);
		searchResult.setTotalCount(totalCount);
		
		long endTime = System.nanoTime();
		
		long duration = endTime - startTime;
		
		searchResult.setTime(TimeUnit.MILLISECONDS.convert(duration, TimeUnit.NANOSECONDS));
		
		return searchResult;
		
	}
	
	@RequestMapping(value = "/forum", method = RequestMethod.GET)
	private @ResponseBody SearchResult searchForum(@RequestParam String query,
			@RequestParam(defaultValue = "1") int pageIndex, @RequestParam(defaultValue = "10") int pageSize) {
			
		long startTime = System.nanoTime();
		
		SearchResult searchResult = new SearchResult();
		
		Map<String, Object> searchDetail = forumDAO.run(query, pageIndex, pageSize);
		
		int totalCount = (Integer) searchDetail.get("totalCount");
		List<SearchDetail> forumSearchDetail = (List<SearchDetail>) searchDetail.get("searchDetailList");
		
		searchResult.setCount(forumSearchDetail.size());
		searchResult.setResult(forumSearchDetail);
		searchResult.setPageIndex(pageIndex);
		searchResult.setPageSize(pageSize);
		searchResult.setTotalCount(totalCount);
		
		long endTime = System.nanoTime();
		
		long duration = endTime - startTime;
		
		searchResult.setTime(TimeUnit.MILLISECONDS.convert(duration, TimeUnit.NANOSECONDS));
		
		return searchResult;
		
	}
	
}
