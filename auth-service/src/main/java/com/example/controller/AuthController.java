package com.example.controller;

import com.example.model.User;
import com.example.repository.UserRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@RestController
public class AuthController {
    
    @Autowired
    private UserRepository userRepository;
    
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    
    @GetMapping("/")
    public String home() {
        return "Welcome to Auth Service!";
    }
    
    @GetMapping("/health")
    public String healthCheck() {
        return "Auth Service is running!";
    }
    
    @PostMapping("/register")
    public User registerUser(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
    
    @GetMapping("/user/{username}")
    public User getUser(@PathVariable String username) {
        return userRepository.findByUsername(username);
    }
}
