package com.cos.security1.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
	
	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Autowired
	UserRepository userRepository;

	// 구글로 부터 받은 userRequest 데이터에 대한 후처리 되는 함수
	// 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		
		// 구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인을 완료 -> Code를 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
		// userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원프로필 받아줌
		System.out.println(super.loadUser(userRequest).getAttributes());
		
		OAuth2User oauth2User = super.loadUser(userRequest);
		
		
		
		String provider = userRequest.getClientRegistration().getClientId();
		String providerId = oauth2User.getAttribute("sub");
		String username = provider + "_" + providerId;
		String password = bCryptPasswordEncoder.encode("1234");
		String email = oauth2User.getAttribute("email");
		String role = "ROLE_USER";
		
		User userEntity = userRepository.findByUsername(username);
		
		if(userEntity == null) {
			User insertUser = new User();
			insertUser.setUsername(username);
			insertUser.setPassword(password);
			insertUser.setEmail(email);
			insertUser.setRole(role);
			insertUser.setProvider(provider);
			insertUser.setProviderId(providerId);
			userRepository.save(insertUser);
			
			return new PrincipalDetails(insertUser, oauth2User.getAttributes());
		}
		
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}

	
	
}
