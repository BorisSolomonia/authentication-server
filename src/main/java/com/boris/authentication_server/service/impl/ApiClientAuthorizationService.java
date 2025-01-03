package com.boris.authentication_server.service.impl;

import com.boris.authentication_server.service.AuthorizationService;
import com.boris.authentication_server.vo.authorization.AuthorizationParam;
import com.boris.authentication_server.vo.authorization.AuthorizationTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//  ეს არის სერვისი რომელიც გამოიყენება ტოკენის გენერირებისთვის, ის რექვესთის ჰედერიდან იღებს პარამეტრებს და აბრუნებს ტოკენს. ის იყენებს პარამეტრებს application.yaml ფაილიდან
//@Service
//public class ApiClientAuthorizationService implements AuthorizationService {
//
//    @Value("${oauth.token-url}")
//    private String oauthTokenUrl;
//
//    @Value("${oauth.api-client-id}")
//    private String clientId;
//
//    @Value("${oauth.api-client-secret}")
//    private String clientSecret;
//
//    @Autowired
//    private RestTemplate restTemplate;
//
////    @Override
////    public AuthorizationTokenResponse generateToken(AuthorizationParam param) {
//////       ეს პარამეტრები გადმოიტანეთ application.yaml ფაილიდან
////        // ეს მეთოდი ქმნის ახალ რექვესთს რომელიც გაგზავნის ტოკენის გენერირებისთვის Authorization სერვერზე, ამ მეთოდში გადმოიტანეთ პარამეტრები რომლებიც გადმოიტანეთ რექვესთის ჰედერიდან
////        HttpHeaders headers = new HttpHeaders(); // ეს არის ჰედერების ობიექტი
////        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED); // ეს არის ჰედერების ტიპი, კონკრეტულად სულ არსებობს რაღაც ტიპის ჰედერები რომლებიც შეიძლება გამოიყენებდეს რექვესთებისთვის. ეს კონკრეტული კი იმას აკეთებს რომ რექვესთის ტიპი იყოს application/x-www-form-urlencoded
////        headers.setBasicAuth(clientId, clientSecret); // ეს არის ბეისიკ ავთორიზაციის ჰედერი, რომელიც არის სტრინგი რომლის ფორმატია არის "მომხმარებელი:პაროლი"
////        param.getHeaderParam().forEach(headers::set); // ეს ციკლი იტერაციას აკეთებს ყველა პარამეტრზე რომლებიც გადმოიტანეთ რექვესთის ჰედერიდან და ყველა პარამეტრს დაამატებს ჰედერებში
////        HttpEntity<String> request = new HttpEntity<>("grant_type=client_credentials", headers);
////        System.out.println("ssssssssssssssssssssss "+request.toString());
////        return restTemplate.postForObject(oauthTokenUrl, request, AuthorizationTokenResponse.class); //ეს არის რექვესთი რომელიც გაგზავნის ტოკენის გენერირებისთვის, oauthTokenUrl არის ტოკენის გენერირების ლინკი, request არის რექვესთის ტიპი და AuthorizationTokenResponse.class არის რესპონსის ტიპი
////    }
//
//
//
//    @Override
//    public AuthorizationTokenResponse generateToken(AuthorizationParam param) {
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//        headers.setBasicAuth(clientId, clientSecret);
//        param.getHeaderParam().forEach(headers::set);
//        HttpEntity<String> request = new HttpEntity<>("grant_type=client_credentials", headers);
//        System.out.println(("Request: {}" +  request.toString()));
//
//        AuthorizationTokenResponse response = restTemplate.postForObject(oauthTokenUrl, request, AuthorizationTokenResponse.class);
//        if (response != null) {
//            System.out.println(("JWT Token: {}" +  response.accessToken()));
//        } else {
//            System.out.println("Failed to generate JWT token.");
//        }
//        return response;
//    }
//
//    private String basicEncodeCredential(String id, String secret) {
//        return Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
//    }
//}

@Service
public class ApiClientAuthorizationService implements AuthorizationService {

    private static final Logger logger = LoggerFactory.getLogger(ApiClientAuthorizationService.class);

    @Value("${oauth.token-url}")
    private String oauthTokenUrl;

    @Value("${oauth.api-client-id}")
    private String clientId;

    @Value("${oauth.api-client-secret}")
    private String clientSecret;

    @Autowired
    private RestTemplate restTemplate;

    @Override
    public AuthorizationTokenResponse generateToken(AuthorizationParam param) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(clientId, clientSecret);
        param.getHeaderParam().forEach(headers::set);
        HttpEntity<String> request = new HttpEntity<>("grant_type=client_credentials", headers);
        logger.info("Request: {}", request.toString());

        try {
            AuthorizationTokenResponse response = restTemplate.postForObject(oauthTokenUrl, request, AuthorizationTokenResponse.class);
            if (response != null) {
                logger.info("JWT Token: {}", response.accessToken());
                return response;
            } else {
                logger.error("Failed to generate JWT token: response is null");
                throw new RuntimeException("Failed to generate JWT token: response is null");
            }
        } catch (Exception e) {
            logger.error("Error generating JWT token", e);
            throw new RuntimeException("Error generating JWT token", e);
        }
    }

    private String basicEncodeCredential(String id, String secret) {
        return Base64.getEncoder().encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }
}
