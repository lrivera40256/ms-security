package com.app.ms_security.Repositories;

import com.app.ms_security.Models.Profile;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface ProfileRepository extends MongoRepository<Profile, String> {
    @Query("{ 'user._id': ?0 }")
    Profile findByUserId(String userId);
}
