package org.anyframe.cloud.user.config;

import org.apache.log4j.MDC;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class AopLoggerConfiguration {
	
	private static final Logger logger = LoggerFactory.getLogger(AopLoggerConfiguration.class);

	@AfterReturning("execution(* org.anyframe.user.application..*.*(..))")
	public void applicationLogService(JoinPoint joinPoint) {
		String methodName = joinPoint.getSignature().toShortString();
		MDC.put("method", methodName);
		logger.info("User application Logger : " + methodName);
	}
	
	@AfterReturning("execution(* org.anyframe.user.interfaces..*.*(..))")
	public void interfacesLogService(JoinPoint joinPoint) {
		String methodName = joinPoint.getSignature().toShortString();
		MDC.put("method", methodName);
		logger.info("User interfaces Logger : " + methodName);
	}
	
	@AfterReturning("execution(* org.anyframe.user.infrastructure..*.*(..))")
	public void infrastructureLogService(JoinPoint joinPoint) {
		String methodName = joinPoint.getSignature().toShortString();
		MDC.put("method", methodName);
		logger.info("User infrastructure Logger : " + methodName);
	}
}
