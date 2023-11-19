package com.example.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController("/")
@Component
public class Controller {
    @GetMapping("/one")
    public int one() {
        return 1;
    }

    @GetMapping("two")
    public int two() {
        return 2;
    }

    @GetMapping("three/{value}")
    public int three(@PathVariable("value") int value) {
        return value;
    }

    @GetMapping("three/or/six/{value}")
    public int threeOrSix(@PathVariable("value") int value) {
        return value;
    }

    @GetMapping("even/{value}")
    @PreAuthorize("@authExpressions.checkIsEven(#value)")
    public int even(@PathVariable("value") int value) {
        return value;
    }
}
