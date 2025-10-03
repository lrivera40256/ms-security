package com.app.ms_security.Entities;
import com.app.ms_security.Models.User;
public class LoginRequest {
    private User user;
    private String token;

    public String getToken() {
        return token;
    }

    public User getUser() {
        return user;
    }
}
