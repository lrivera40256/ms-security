package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Photo;
import com.app.ms_security.Models.Profile;
import com.app.ms_security.Models.User;
import com.app.ms_security.Repositories.PhotoRepository;
import com.app.ms_security.Repositories.ProfileRepository;
import com.app.ms_security.Repositories.UserRepository;
import com.app.ms_security.Services.CloudinaryService;
import com.app.ms_security.Services.EncryptionService;
import com.app.ms_security.Services.ValidatorsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/profiles")
public class ProfilesController {
    @Autowired
    private ValidatorsService validatorService;
    @Autowired
    private ProfileRepository theProfilesRepository;
    @Autowired
    private UserRepository theUserRepository;
    @Autowired
    private PhotoRepository photoRepository;
    @Autowired
    private EncryptionService encryptionService;
    @Autowired
    private CloudinaryService cloudinaryService;

    @GetMapping("")
    public List<Profile> find() {
        return this.theProfilesRepository.findAll();
    }

    @GetMapping("{id}")
    public Profile findById(@PathVariable String id) {
        return this.theProfilesRepository.findById(id).orElse(null);
    }

    @PostMapping
    public Profile create(@RequestBody Profile newProfiles) {
        return this.theProfilesRepository.save(newProfiles);
    }

    @PatchMapping("{id}")
    public Profile patchProfile(@PathVariable String id, @RequestBody Map<String, Object> changes) {
        Profile profile = theProfilesRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Perfil no encontrado"));

        if (changes.containsKey("phone")) {
            profile.setPhone((String) changes.get("phone"));
        }

        if (changes.containsKey("photoId")) {
            String photoId = (String) changes.get("photoId");
            photoRepository.findById(photoId).ifPresent(profile::setPhoto);
        }

        // Actualizar URL sin crear nueva entidad
        if (changes.containsKey("photoUrl")) {
            String photoUrl = (String) changes.get("photoUrl");
            if (photoUrl != null && !photoUrl.isBlank()) {
                Photo p = profile.getPhoto();
                if (p == null) {
                    p = new Photo(photoUrl);
                } else {
                    p.setUrl(photoUrl);
                }
                p = photoRepository.save(p);
                profile.setPhoto(p);
            }
        }

        // Campo genérico "photo" (reutiliza si existe)
        if (changes.containsKey("photo")) {
            String value = (String) changes.get("photo");
            if (value != null && !value.isBlank()) {
                Photo p = profile.getPhoto();
                if (p == null) {
                    p = new Photo(value);
                } else {
                    p.setUrl(value);
                }
                p = photoRepository.save(p);
                profile.setPhoto(p);
            }
        }

        if (changes.containsKey("user") && changes.get("user") instanceof Map<?, ?> m) {
            User u = profile.getUser();
            if (u != null) {
                if (m.containsKey("name")) u.setName((String) m.get("name"));
                if (m.containsKey("email")) u.setEmail((String) m.get("email"));
                theUserRepository.save(u);
            }
        }

        return theProfilesRepository.save(profile);
    }

    @PatchMapping("{id}/password")
    public void changePassword(@PathVariable String id, @RequestBody Map<String, String> body) {
        String current = body.get("currentPassword");
        String next = body.get("newPassword");
        if (current == null || next == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Faltan campos");
        }
        Profile profile = theProfilesRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Perfil no encontrado"));
        User u = profile.getUser();
        if (u == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Sin usuario");
        if (Boolean.TRUE.equals(u.getIsOauth())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cuenta OAuth no cambia contraseña");
        }
        String currentHash = encryptionService.convertSHA256(current);
        if (!currentHash.equals(u.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Contraseña actual incorrecta");
        }
        u.setPassword(encryptionService.convertSHA256(next));
        theUserRepository.save(u);
    }

    @PatchMapping(value = "{id}/photo/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Profile uploadAndSetPhoto(@PathVariable String id,
                                     @RequestPart("file") MultipartFile file) throws Exception {
        if (file == null || file.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Archivo vacío");
        }
        Profile profile = theProfilesRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Perfil no encontrado"));

        String url = cloudinaryService.uploadFile(file);

        Photo photo = profile.getPhoto();
        if (photo == null) {
            photo = new Photo(url);
        } else {
            photo.setUrl(url);
        }
        photo = photoRepository.save(photo);
        profile.setPhoto(photo);
        return theProfilesRepository.save(profile);
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        Profile p = this.theProfilesRepository.findById(id).orElse(null);
        if (p != null) {
            this.theProfilesRepository.delete(p);
        }
    }

    @GetMapping("/user")
    public Profile findByUserId(HttpServletRequest request) {
        User theUser = validatorService.getUser(request);
        return this.theProfilesRepository.findByUserId(theUser.get_id());
    }

    @PatchMapping("{id}/twoFa")
    public Map<String,Object> toggle2FA(@PathVariable String id, @RequestBody Map<String,Boolean> body){
        Boolean enable = body.get("enable");
        if (enable == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Falta enable");
        Profile profile = theProfilesRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Perfil no encontrado"));
        if (profile.getUser()!=null && Boolean.TRUE.equals(profile.getUser().getIsOauth())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"OAuth no usa este 2FA");
        }
        profile.setTwoFactorEnabled(enable);
        theProfilesRepository.save(profile);
        return Map.of("twoFactorEnabled", profile.getTwoFactorEnabled());
    }
}
