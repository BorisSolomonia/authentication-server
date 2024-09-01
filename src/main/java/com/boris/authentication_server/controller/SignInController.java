package com.boris.authentication_server.controller;

import com.boris.authentication_server.constant.Provider;
import com.boris.authentication_server.dto.AuthenticationDTO;
import com.boris.authentication_server.service.impl.SignInUserAuthenticationService;
import com.boris.authentication_server.vo.authentication.AuthenticationResponse;
import com.boris.authentication_server.vo.request.AuthenticationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

import static com.boris.authentication_server.controller.ControllerConstant.END_POINT;

@RestController
@RequestMapping(END_POINT+"/sign-in")
public class SignInController {

    @Autowired
    private SignInUserAuthenticationService signInUserAuthenticationService;

    @PostMapping("/sign")
    public ResponseEntity<AuthenticationResponse> signIn(@RequestBody AuthenticationRequest request) {
        if (Objects.isNull(request)) {
            System.out.println("wwwwwwwwwwwwwwwwww");
        }
        System.out.println("request ----------------------AAAAAAAAAAAAAA = " + request.username());
        return new ResponseEntity<>(signInUserAuthenticationService
                .authenticate(AuthenticationDTO.builder() // ეს იმიტიომ არის საჭირო რომ საინ ინ კლასში დტო არის
                        .username(request.username())
                .password(request.password()).provider(Provider.LOCAL)
                        .build()),HttpStatus.OK);
    }
}
