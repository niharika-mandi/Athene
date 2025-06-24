package com.example.authservice.controller;

import com.example.authservice.model.User;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.security.JwtUtils;
import com.example.authservice.service.UserDetailsServiceImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	private final AuthenticationManager authenticationManager;
    private final UserDetailsServiceImpl userDetailsService;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AuthenticationManager authenticationManager,
                          UserDetailsServiceImpl userDetailsService,
                          JwtUtils jwtUtils,
                          UserRepository userRepository,
                          PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtUtils = jwtUtils;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Request body for signup
    record SignupRequest(String username, String password) {}

    // Request body for login
    record LoginRequest(String username, String password) {}

    // Request body for token refresh
    record RefreshTokenRequest(String refreshToken) {}

    // Response body for authentication
    record AuthResponse(String accessToken, String refreshToken, String message) {}

    /**
     * Handles user registration.
     * Encodes the password and saves the new user to the database.
     * @param signupRequest The signup request containing username and password.
     * @return ResponseEntity with success or error message.
     */
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest signupRequest) {
        // Check if username already exists
        if (userRepository.findByUsername(signupRequest.username()).isPresent()) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, null, "Username already taken!"));
        }

        // Create new user account
        User user = new User(signupRequest.username(),
                             passwordEncoder.encode(signupRequest.password()));
        userRepository.save(user);

        return ResponseEntity.ok(new AuthResponse(null, null, "User registered successfully!"));
    }

    /**
     * Handles user login and generates JWT tokens.
     * Authenticates user credentials and generates an access token and a refresh token.
     * @param loginRequest The login request containing username and password.
     * @return ResponseEntity with access token, refresh token, or error message.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Authenticate user credentials
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password())
            );
        } catch (BadCredentialsException e) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, null, "Invalid username or password!"));
        }

        // Load user details and generate tokens
        final UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.username());
        final String accessToken = jwtUtils.generateToken(userDetails);
        final String refreshToken = jwtUtils.generateRefreshToken(userDetails);

        // Save refresh token to the database
        User user = (User) userDetails;
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken, "Login successful!"));
    }

    /**
     * Handles refresh token requests to get a new access token.
     * Validates the refresh token and issues a new access token.
     * @param refreshTokenRequest The refresh token request containing the refresh token.
     * @return ResponseEntity with a new access token or error message.
     */
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        String requestRefreshToken = refreshTokenRequest.refreshToken();

        // Validate refresh token
        if (!jwtUtils.validateToken(requestRefreshToken)) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, null, "Invalid or expired refresh token!"));
        }

        String username = jwtUtils.extractUsername(requestRefreshToken);
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty() || !userOptional.get().getRefreshToken().equals(requestRefreshToken)) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, null, "Invalid refresh token for user!"));
        }

        // Generate new access token
        UserDetails userDetails = userOptional.get();
        String newAccessToken = jwtUtils.generateToken(userDetails);

        return ResponseEntity.ok(new AuthResponse(newAccessToken, requestRefreshToken, "Access token refreshed!"));
    }

    // Example of a protected endpoint
    @GetMapping("/protected")
    public ResponseEntity<String> protectedEndpoint() {
        return ResponseEntity.ok("This is a protected endpoint! You are authenticated.");
    }

}
