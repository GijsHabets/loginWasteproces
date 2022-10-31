package com.example.demo;

import com.example.demo.Config.RsaKeyproperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RsaKeyproperties.class)
@SpringBootApplication
public class DemoGijsApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoGijsApplication.class, args);
	}

}
