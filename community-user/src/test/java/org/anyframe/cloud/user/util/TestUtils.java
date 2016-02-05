package org.anyframe.cloud.user.util;

import org.springframework.aop.framework.Advised;
import org.springframework.aop.support.AopUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

public class TestUtils {
	
	/**
     * If the given object is a proxy, set the return value as the object
     * being proxied, otherwise return the given object.
     */
	public static final Object unwrapProxy(Object bean) throws Exception {
	    if (AopUtils.isAopProxy(bean) && bean instanceof Advised) {
	        Advised advised = (Advised) bean;
	        bean = advised.getTargetSource().getTarget();
	    }
	    return bean;
	}

	public static String asJsonString(final Object obj) {
	    try {
	        final ObjectMapper mapper = new ObjectMapper();
	        final String jsonContent = mapper.writeValueAsString(obj);
	        return jsonContent;
	    } catch (Exception e) {
	        throw new RuntimeException(e);
	    }
	}  

}
