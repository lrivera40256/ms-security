package com.app.ms_security.Entities;
import com.app.ms_security.Models.User;
public class LoginRequest {
    private User user;
    private String token;
    private String captcha;

    public String getToken() {
        return token;
    }

    public User getUser() {
        return user;
    }

    public String getCaptcha() { return captcha; }
}
