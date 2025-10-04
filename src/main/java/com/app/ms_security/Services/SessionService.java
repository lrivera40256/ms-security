package com.app.ms_security.Services;

import com.app.ms_security.Models.Session;
import com.app.ms_security.Repositories.SessionRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SessionService {

    private final SessionRepository sessionRepository;

    public SessionService(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    // Elimina todas las sesiones asociadas al usuario (p.ej. al cerrar sesión)
    public void deleteAllByUser(String userId) {
        List<Session> sessions = sessionRepository.findAllByUserId(userId);
        if (!sessions.isEmpty()) {
            sessionRepository.deleteAll(sessions);
        }
    }

    // (Opcional) Elimina una sola sesión (por id)
    public void deleteById(String sessionId) {
        sessionRepository.deleteById(sessionId);
    }
}