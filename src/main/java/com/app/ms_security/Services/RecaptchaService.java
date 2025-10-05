package com.app.ms_security.Services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class RecaptchaService {
    private final WebClient webClient;
    private final String secret;

    public RecaptchaService(@Value("${security.captcha.recaptcha.secret}") String secret) {
        this.webClient = WebClient.builder()
                .baseUrl("https://www.google.com/recaptcha/api")
                .build();
        this.secret = secret;
    }

    public RecaptchaVerifyResponse verify(String token, String remoteIp) {
        return webClient.post()
                .uri("/siteverify")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue("secret=" + secret +
                        "&response=" + token +
                        (remoteIp != null ? "&remoteip=" + remoteIp : ""))
                .retrieve()
                .bodyToMono(RecaptchaVerifyResponse.class)
                .block();
    }

    // v2/v3: Google responde con este shape
    public static record RecaptchaVerifyResponse(
            boolean success,
            String challenge_ts,
            String hostname,
            String action,     // v3
            Float score,       // v3
            String[] errorCodes
    ) {}
}