package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;


@Controller
public class IndexController {
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	private UserRepository userRepository;

	
	@GetMapping({"", "/"})
	@ResponseBody
	public String index() {
		return "index";
	}
	
	@GetMapping("/user")
	@ResponseBody
	public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("PrincipalDetails ::: " + principalDetails.getUser());
		return "user";
	}
	
	@GetMapping("/admin")
	@ResponseBody
	public String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	@ResponseBody
	public String manager() {
		return "manager";
	}
	
	// 스프링 시큐리티가 "/login"을 낚아챈다.
	@GetMapping("/login")
	@ResponseBody
	public String login() {
		return "login";
	}
	
	@GetMapping("/joinProc")
	@ResponseBody
	public String joinProc() {
		return "joinProc";
	}

	@PostMapping("/join")
	public String join(User user) {

		user.setRole("ROLE_USER");
		
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		
		userRepository.save(user);
		
		return "redirect:/loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	
	@Secured("ROLE_ADMIN")
	@GetMapping("/info")
	@ResponseBody
	public String info() {
		return "개인정보";
	}
	
	@PostAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
//	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	@GetMapping("/data")
	@ResponseBody
	public String data() {
		return "데이터정보";
	}
	
	@GetMapping("/test/login")
	@ResponseBody
	public String testLogin(
			Authentication authentication, 
			@AuthenticationPrincipal PrincipalDetails userDetails) {
		
		System.out.println("Test Login !!!");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication ::: " + principalDetails.getUser());
		System.out.println("userDetails ::: " + userDetails.getUser());
		
		return "세션 정보 확인하기";
	}
	
	@GetMapping("/test/oauth/login")
	@ResponseBody
	public String testOauthLogin(
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oauth) {
		
		System.out.println("Test Login !!!");
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication ::: " + oauth2User.getAttributes());
		System.out.println("oauth2User ::: " + oauth.getAttributes());
		
		return "세션 정보 확인하기";
	}
	
}
