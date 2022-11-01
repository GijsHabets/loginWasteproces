package com.example.demo;

import com.example.demo.Config.RsaKeyproperties;
import com.example.demo.Model.User;
import com.example.demo.Repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableConfigurationProperties(RsaKeyproperties.class)
@SpringBootApplication
public class DemoGijsApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoGijsApplication.class, args);
	}
	@Bean
	CommandLineRunner commandLineRunner(UserRepository users, PasswordEncoder encoder){
		return args -> {
			users.save(new User("Gijs",encoder.encode("1234"),"ROLE_ADMIN"));
			users.save(new User("user",encoder.encode("1234"),"ROLE_USER"));
			users.save(new User("admin",encoder.encode("1234"),"ROLE_ADMIN"));
		};
	}

}
