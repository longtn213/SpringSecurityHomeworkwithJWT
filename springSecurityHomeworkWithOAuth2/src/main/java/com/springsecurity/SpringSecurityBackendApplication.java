package com.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
//@EnableWebSecurity(debug = true) //Optional help all feature of Spring Security will be enabled
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true,jsr250Enabled = true) // help enable level security
public class SpringSecurityBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityBackendApplication.class, args);
	}

}
