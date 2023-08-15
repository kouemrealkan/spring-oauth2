package com.alkan.securitydemov1.federated;

import com.alkan.securitydemov1.data.entity.SocialUser;
import com.alkan.securitydemov1.data.repository.SocialUserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.function.Consumer;

@Slf4j
public final class UserRepositoryOAuth2UserHandler implements Consumer<OAuth2User> {

    private final SocialUserRepository socialUserRepository;

    public UserRepositoryOAuth2UserHandler(SocialUserRepository socialUserRepository) {
        this.socialUserRepository = socialUserRepository;
    }

    @Override
    public void accept(OAuth2User user) {
        if (!this.socialUserRepository.findByEmail(user.getName()).isPresent()) {
            SocialUser socialUser = SocialUser.fromOauthUser(user);
            log.info(socialUser.toString());
            System.out.println(socialUser);
            socialUserRepository.save(socialUser);
        } else {
            log.info("Hoşgeldiniz ", user.getAttributes().get("given_name"));
        }
    }

}
