package com.ellen.book.springboot.config.auth;

import com.ellen.book.springboot.config.auth.dto.OAuthAttributes;
import com.ellen.book.springboot.config.auth.dto.SessionUser;
import com.ellen.book.springboot.config.auth.domain.user.User;
import com.ellen.book.springboot.config.auth.domain.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.util.Collections;

@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final HttpSession httpSession;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // 서비스 구분용 id (구글/네이버/페북/카카오 등)
        String registrationId = userRequest
                .getClientRegistration().getRegistrationId();

        // 로그인 시 PK가 되는 필드 값(구글: sub, 페북),)
        String userNameAttributeName = userRequest
                .getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        // 소셜 로그인 된 유저 정보, 이를 객체화
        OAuthAttributes attributes = OAuthAttributes.
                of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // 사용자 정보 업데이트
        User user = saveOrUpdate(attributes);

        // 세션에 사용자 정보를 등록
        httpSession.setAttribute("user", new SessionUser(user));

        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRoleKey())),
                attributes.getAttributes(),
                attributes.getNameAttributeKey()
        );

    }

    private User saveOrUpdate(OAuthAttributes attributes){
        User user = userRepository.findByEmail(attributes.getEmail())
                .map(
                        entity -> entity.update(attributes.getName(), attributes.getPicture())
                )
                .orElse(attributes.toEntity());
        return userRepository.save(user);
    }
}
