package org.anyframe.cloud.user.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

public class CargoUserFilter implements Filter {

	private static final Logger logger = LoggerFactory
			.getLogger(CargoUserFilter.class);

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// TODO Auto-generated method stub

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException {
		// TODO Auto-generated method stub
		String txId = ((HttpServletRequest) request).getHeader("txId");
		String spanId = ((HttpServletRequest) request).getHeader("spanId");
		String originAddr = ((HttpServletRequest) request).getHeader("x-forwarded-for");
		
		if (txId != null) {
			MDC.put("txId", txId);
			MDC.put("spanId", spanId);
			MDC.put("x-forwarded-for", originAddr);
		}
		
//		logger.info("CargoUserFilter run txId : " + txId + " & spanID : " + spanId);
		
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
	}

}