package com.boris.authentication_server.vo.authorization;

import com.fasterxml.jackson.annotation.JsonProperty;

// ეს კლასი არის რესპონსი რომელიც აბრუნებს ტოკენს, ამ კლასს იყენებს AuthorizationService კლასი
public record AuthorizationTokenResponse(@JsonProperty("access_token") String accessToken) {

}
