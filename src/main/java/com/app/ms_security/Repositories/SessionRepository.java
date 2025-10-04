package com.app.ms_security.Repositories;

import com.app.ms_security.Models.Session;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SessionRepository extends MongoRepository<Session, String> {

    // Busca sesión por email del usuario + código 2FA
    @Query("{ 'user.email': ?0, 'code2FA': ?1 }")
    Session findByUserEmailAndCode2FA(String email, String code2FA);

    // Lista sesiones por id de usuario (campo _id en el documento user)
    @Query("{ 'user._id': ?0 }")
    List<Session> findAllByUserId(String userId);
}
