package com.example.demo;

import com.example.demo.security.jwt.JwtAuthenticationToken;
import com.example.demo.security.model.UserContext;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}
}

@RestController
class TestRest {

    @RequestMapping("/api/login")
    @ResponseBody
    public String login(JwtAuthenticationToken token) {
        UserContext principalUser = (UserContext) token.getPrincipal();
        return "Hello, " + principalUser.getUsername() + " !";
    }

}
