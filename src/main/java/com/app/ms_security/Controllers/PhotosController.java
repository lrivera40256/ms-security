package com.app.ms_security.Controllers;

import com.app.ms_security.Models.Photo;
import com.app.ms_security.Services.CloudinaryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.app.ms_security.Repositories.PhotoRepository;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/photos")
public class PhotosController {

    @Autowired
    private PhotoRepository thePhotoRepository;

    @Autowired
    private CloudinaryService theCloudinaryService;

    @GetMapping("")
    public List<Photo> find() {
        return this.thePhotoRepository.findAll();
    }

    @GetMapping("{id}")
    public Photo findById(@PathVariable String id) {
        return this.thePhotoRepository.findById(id).orElse(null);
    }

    @PostMapping("/upload")
    public Photo upload(@RequestParam("file") MultipartFile file) throws Exception {
        String url = theCloudinaryService.uploadFile(file);
        Photo photo = new Photo(url);
        return this.thePhotoRepository.save(photo);
    }

    @PostMapping("/oauth")
    public Photo saveOAuthPhoto(@RequestParam("url") String photoUrl) {
        Photo photo = new Photo(photoUrl);
        return this.thePhotoRepository.save(photo);
    }

    /* @GetMapping("/view/{id}")
    public ResponseEntity<byte[]> view(@PathVariable String id) {
        Photo photo = this.thePhotoRepository.findById(id).orElse(null);
        if (photo == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(photo.getContentType()))
                .body(photo.getData());
    }
    */

    @PutMapping("{id}")
    public Photo update(@PathVariable String id, @RequestParam("file") MultipartFile file) throws Exception {
        Photo actualPhoto = this.thePhotoRepository.findById(id).orElse(null);
        if (actualPhoto != null) {
            String url = theCloudinaryService.uploadFile(file);
            actualPhoto.setUrl(url);
            return this.thePhotoRepository.save(actualPhoto);
        }
        return null;
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        this.thePhotoRepository.deleteById(id);
    }
}
