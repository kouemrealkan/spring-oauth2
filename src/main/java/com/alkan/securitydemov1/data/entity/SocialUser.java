package com.alkan.securitydemov1.data.entity;

import com.alkan.securitydemov1.common.data.entity.IdEntity;
import jakarta.persistence.Entity;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Entity
@Getter
@Setter
@Builder
public class SocialUser extends IdEntity {

    private String email;
    private String name;
    private String givenName;
    private String imageUrl;

    public SocialUser() {

    }

    public SocialUser(String email, String name, String givenName, String imageUrl) {
        this.email = email;
        this.name = name;
        this.givenName = givenName;
        this.imageUrl = imageUrl;
    }

    @Override
    public String toString() {
        return "SocialUser{" +
                "email='" + email + '\'' +
                ", name='" + name + '\'' +
                ", givenName='" + givenName + '\'' +
                ", imageUrl='" + imageUrl + '\'' +
                ", identifier='" + identifier + '\'' +
                '}';
    }

    public static SocialUser fromOauthUser(OAuth2User user) {
        return SocialUser.builder()
                .email(user.getName())
                .name(user.getAttributes().get("name").toString())
                .givenName(user.getAttributes().get("given_name").toString())
                .imageUrl(user.getAttributes().get("picture").toString())
                .build();
    }
}
