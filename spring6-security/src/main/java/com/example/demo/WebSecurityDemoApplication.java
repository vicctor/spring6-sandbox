package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;

@SpringBootApplication
public class WebSecurityDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(WebSecurityDemoApplication.class, args);
    }

    @Component("authExpressions")
    public static class WebSecurity {
        public boolean checkIsEven(int value) {
                return value % 2 == 0;
        }
    }

}
