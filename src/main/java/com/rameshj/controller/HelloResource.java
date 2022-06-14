package com.rameshj.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.rameshj.model.JWTRequest;
import com.rameshj.model.JWTResponse;
import com.rameshj.security.MyUserDetailsService;
import com.rameshj.utility.JWTUtility;

@RestController
public class HelloResource {
    @Autowired
    private JWTUtility jwtUtility;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService userService;
	
	@GetMapping("/")
	public String sayHello() {
		return "<h2>Hello</h2>";
	}
	
	@PostMapping("/authenticate")
    public JWTResponse authenticate(@RequestBody JWTRequest jwtRequest,HttpServletRequest request) throws Exception{

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            jwtRequest.getUserName(),
                            jwtRequest.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }

        final UserDetails userDetails
                = userService.loadUserByUsername(jwtRequest.getUserName());

        final String token =
                jwtUtility.generateToken(userDetails);
        System.out.println( request.getHeader("Authorization"));
        return  new JWTResponse(token);
    }
}
