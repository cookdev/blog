package org.anyframe.cloud.user.filter;

import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;

import ch.qos.logback.access.tomcat.LogbackValve;

public class CargoUserServletContainer implements
		EmbeddedServletContainerCustomizer {

	@Override
	public void customize(
			ConfigurableEmbeddedServletContainer paramConfigurableEmbeddedServletContainer) {

		if (paramConfigurableEmbeddedServletContainer instanceof TomcatEmbeddedServletContainerFactory) {

			TomcatEmbeddedServletContainerFactory tomcatEmbeddedServletContainerFactory = (TomcatEmbeddedServletContainerFactory) paramConfigurableEmbeddedServletContainer;

			LogbackValve logbackValve = new LogbackValve();
			logbackValve.setFilename("src/main/resources/logback-access.xml");
			tomcatEmbeddedServletContainerFactory
					.addContextValves(logbackValve);

		}

	}

}