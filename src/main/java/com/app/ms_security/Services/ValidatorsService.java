package com.app.ms_security.Services;


import com.app.ms_security.Models.User;
import com.app.ms_security.Models.*;
import com.app.ms_security.Repositories.PermissionRepository;
import com.app.ms_security.Repositories.RolePermissionRepository;
import com.app.ms_security.Repositories.UserRepository;
import com.app.ms_security.Repositories.UserRoleRepository;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ValidatorsService {
    @Autowired
    private FirebaseAuth firebaseAuth;
    @Autowired
    private JwtService jwtService;

    @Autowired
    private PermissionRepository thePermissionRepository;
    @Autowired
    private UserRepository theUserRepository;
    @Autowired
    private RolePermissionRepository theRolePermissionRepository;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

    private static final String BEARER_PREFIX = "Bearer ";

    public boolean validationRolePermission(HttpServletRequest request,
                                            HttpServletResponse response,
                                            String url,
                                            String method) {
        boolean success = false;
        User theUser = this.getUser(request);
        if (theUser != null) {
            System.out.println("Antes URL " + url + " metodo " + method);
            url = url.replaceAll("[0-9a-fA-F]{24}|\\d+", "?");
            System.out.println("URL " + url + " metodo " + method);
            Permission thePermission = this.thePermissionRepository.getPermission(url, method);

            List<UserRole> roles = this.theUserRoleRepository.getRolesByUser(theUser.get_id());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            int i = 0;
            while (i < roles.size() && success == false) {
                UserRole actual = roles.get(i);
                Role theRole = actual.getRole();
                if (theRole != null && thePermission != null) {
                    System.out.println("Rol " + theRole.get_id() + " Permission " + thePermission.get_id());
                    RolePermission theRolePermission = this.theRolePermissionRepository.getRolePermission(theRole.get_id(), thePermission.get_id());
                    if (theRolePermission != null) {
                        response.setStatus(HttpServletResponse.SC_OK);
                        success = true;
                    }
                } else {
                    success = false;
                }
                i += 1;
            }

        }else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

        return success;
    }
        

    public User getUser(final HttpServletRequest request) {
        User theUser = null;
        String authorizationHeader = request.getHeader("Authorization");
        System.out.println("Header " + authorizationHeader);
        String token;
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            token = authorizationHeader.substring(BEARER_PREFIX.length());
            System.out.println("Bearer Token: " + token);
            User theUserFromToken = jwtService.getUserFromToken(token);
            if (theUserFromToken != null) {
                theUser = this.theUserRepository.findById(theUserFromToken.get_id())
                        .orElse(null);

            } else {

                try {
                    FirebaseToken decoded = firebaseAuth.verifyIdToken(token, true);
                    String email = decoded.getEmail();
                    theUser = this.theUserRepository.getUserByEmail(email);
                } catch (Exception e) {
                    theUser = null;
                }

            }
        }
        return theUser;
    }
}
