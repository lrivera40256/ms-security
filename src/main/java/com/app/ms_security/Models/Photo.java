package com.app.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class Photo {
    @Id
    private String _id;
    private String url;

    public Photo() {}

    public Photo(String url) {
        this.url = url;
    }
}
