package org.anyframe.cloud.user.filter;

import java.io.IOException;

import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

public class RestTemplateInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(
            HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {

        HttpHeaders headers = request.getHeaders();
        headers.add("txId", MDC.get("txId"));        

        int tempSpanId = Integer.parseInt(MDC.get("spanId")) + 1;
        MDC.put("spanId", Integer.toString(tempSpanId));
        headers.add("spanId", Integer.toString(tempSpanId));     
        
        headers.add("x-forwarded-for", MDC.get("x-forwarded-for")); 
        
        return execution.execute(request, body);
    }
}