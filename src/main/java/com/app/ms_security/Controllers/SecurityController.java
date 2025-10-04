package com.app.ms_security.Controllers;

import com.app.ms_security.Configurations.FirebaseConfig;
import com.app.ms_security.Entities.LoginRequest;
import com.app.ms_security.Models.*;
import com.app.ms_security.Repositories.PhotoRepository;
import com.app.ms_security.Repositories.ProfileRepository;
import com.app.ms_security.Repositories.SessionRepository;
import com.app.ms_security.Repositories.UserRepository;
import com.app.ms_security.Services.*;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;


import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@CrossOrigin
@RestController
@RequestMapping("/api/public/security")
public class SecurityController {
    @Autowired
    private UserRepository theUserRepository;
    @Autowired
    private EncryptionService theEncryptionService;
    @Autowired
    private JwtService theJwtService;
    @Autowired
    private NotificationService theNotificationService;
    @Autowired
    private SessionRepository theSessionRepository;
    @Autowired
    private ProfileRepository theProfileRepository;
    @Autowired
    private FirebaseAuth firebaseAuth;
    @Autowired
    private AuthServices authServices;
    @Autowired
    private SessionService sessionService;
    @Autowired
    private PhotoRepository thePhotoRepository;

    private ValidatorsService theValidatorsService;

    @PostMapping("permissions-validation")
    public boolean permissionsValidation(final HttpServletRequest request,
                                         @RequestBody Permission thePermission) {
        boolean success = this.theValidatorsService.validationRolePermission(request, thePermission.getUrl(), thePermission.getMethod());
        return success;
    }

    /*
    @PostMapping("login")
    public HashMap<String,Object> login(@RequestBody User theNewUser,
                                        final HttpServletResponse response)throws IOException {
        HashMap<String,Object> theResponse=new HashMap<>();
        String token="";
        User theActualUser=this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        if(theActualUser!=null &&
           theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))){
            token=theJwtService.generateToken(theActualUser);
            theActualUser.setPassword("");
            theResponse.put("token",token);
            theResponse.put("user",theActualUser);
            return theResponse;
        }else{
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return  theResponse;
        }
    }
    */

    public HashMap<String, Object> loginOauth(HashMap<String, Object> theResponse, String idToken) throws IOException {

        if (idToken == null) {
            theResponse.put("status", HttpServletResponse.SC_BAD_REQUEST);
            return theResponse;
        }
        try {
            FirebaseToken decoded = firebaseAuth.verifyIdToken(idToken, true);
            String email = decoded.getEmail();
            String name = decoded.getName();
            String photo = decoded.getPicture();

            if (email == null || email.isBlank()) theResponse.put("status", HttpServletResponse.SC_BAD_REQUEST);
            User theActualUser = this.theUserRepository.getUserByEmail(email);
            if (theActualUser == null) {
                theActualUser = new User();
                theActualUser.setEmail(email);
                theActualUser.setName(name);
                theActualUser.setIsOauth(true);
                Photo thePhoto = new Photo();
                thePhoto.setUrl(photo);
                thePhoto=thePhotoRepository.save(thePhoto);

                theActualUser = theUserRepository.save(theActualUser);
                Profile theProfile = new Profile(null, theActualUser, thePhoto);
                theProfileRepository.save(theProfile);
            }
            if (!theActualUser.getIsOauth()) {
                theResponse.put("status", HttpServletResponse.SC_UNAUTHORIZED);
                return theResponse;
            }

            theResponse.put("status", HttpServletResponse.SC_OK);
        } catch (Exception e) {
            theResponse.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            theResponse.put("message", e.getMessage());
        }

        return theResponse;
    }

    // ...existing code...
    public HashMap<String, Object> loginJwt(HashMap<String, Object> theResponse,
                                            User theActualUser,
                                            User theNewUser) {
        // Validaciones básicas
        if (theActualUser == null ||
                Boolean.TRUE.equals(theActualUser.getIsOauth()) ||
                !theActualUser.getPassword()
                        .equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))) {
            theResponse.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            return theResponse;
        }

        // Obtener (o crear) Profile
        Profile profile = theProfileRepository.findByUserId(theActualUser.get_id());
        if (profile == null) {
            profile = new Profile(null, theActualUser, null);
            profile = theProfileRepository.save(profile);
        }

        if (Boolean.TRUE.equals(profile.getTwoFactorEnabled())) {
            String code2FA = theNotificationService.generateCode2FA();
            theNotificationService.send2FACode(theActualUser.getEmail(), code2FA);
            Date codeExpiration = new Date(System.currentTimeMillis() + 10 * 60 * 1000);

            Session session = new Session(null, codeExpiration, code2FA);
            session.setUser(theActualUser);
            session.setIntentos(0);
            Session savedSession = theSessionRepository.save(session);

            theResponse.put("2fa_required", true);
            theResponse.put("message", "Código 2FA enviado al correo");
            theResponse.put("sessionId", savedSession.get_id());
            return theResponse;
        }

        // Sin 2FA: emitir token directo
        String token = theJwtService.generateToken(theActualUser);
        List<Permission> permissions = authServices.getRolesByUser(theActualUser);
        Session session = new Session(token, null, null);
        session.setUser(theActualUser);
        Session savedSession = theSessionRepository.save(session);
        theResponse.put("2fa_required", false);
        theResponse.put("token", token);
        theResponse.put("permissions", permissions);
        return theResponse;
    }


    @PostMapping("login")
    public HashMap<String, Object> login(@RequestBody LoginRequest request,
                                         final HttpServletResponse response) throws IOException {
        HashMap<String, Object> theResponse = new HashMap<>();
        User theNewUser = request.getUser();
        if (theNewUser != null) {
            theResponse = loginJwt(theResponse, this.theUserRepository.getUserByEmail(theNewUser.getEmail()), theNewUser);
        } else {
            theResponse = loginOauth(theResponse, request.getToken());
        }
        return theResponse;

    }


    @PostMapping("validate-2fa")
    public HashMap<String, Object> validate2FA(@RequestBody Map<String, String> body,
                                               final HttpServletResponse response) throws IOException {
        HashMap<String, Object> theResponse = new HashMap<>();
        String sessionId = body.get("sessionId");
        String code = body.get("code");
        Session session = this.theSessionRepository.findById(sessionId).orElse(null);

        if (session.getExpiration() != null && session.getExpiration().before(new Date()) ||
                session.getIntentos() >= 3) {
            if (session != null) {
                this.theSessionRepository.delete(session);
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Sesión expirada o intentos excedidos");
            return theResponse;
        }

        if (session != null && session.getCode2FA().equals(code)) {
            User theActualUser = session.getUser();
            String token = theJwtService.generateToken(theActualUser);

            session.setToken(token);
            session.setCode2FA(null);
            session.setExpiration(null);
            session.setIntentos(0);
            this.theSessionRepository.save(session);

            this.theNotificationService.sendLoginNotification(
                    theActualUser.getEmail(),
                    theActualUser.getName(),
                    LocalDateTime.now().toString()
            );
            List<Permission> permissions = authServices.getRolesByUser(theActualUser);
            theResponse.put("permissions", permissions);
            theResponse.put("valid", true);
            theResponse.put("token", token);
            return theResponse;
        } else {
            session.setIntentos(session.getIntentos() + 1);
            this.theSessionRepository.save(session);
            int restantes = Math.max(0, 3 - session.getIntentos());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    "Código incorrecto. Intentos restantes: " + restantes);
            return theResponse;
        }
    }

    @PostMapping("register")
    public User register(@RequestBody User newUser) throws Exception {
        User theUser = this.theUserRepository.getUserByEmail(newUser.getEmail());
        if (theUser == null) {
            newUser.setPassword(this.theEncryptionService.convertSHA256(newUser.getPassword()));
            return this.theUserRepository.save(newUser);
        } else {
            throw new Exception("El usuario ya existe");
        }
    }

    @DeleteMapping("logout")
    public Map<String, Object> logout(@RequestHeader(name = "Authorization", required = false) String authorization) {
        if (authorization == null || authorization.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Falta header Authorization");
        }
        String rawToken = authorization.startsWith("Bearer ") ? authorization.substring(7) : authorization;
        User user = theJwtService.getUserFromToken(rawToken);
        if (user == null || user.get_id() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token inválido");
        }
        sessionService.deleteAllByUser(user.get_id());
        return Map.of("status", "ok", "message", "Logout exitoso");
    }
}
