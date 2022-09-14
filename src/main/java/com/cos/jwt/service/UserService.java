package com.cos.jwt.service;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    @Autowired
    UserRepository userRepository;

    @Transactional
    public void updateRefreshToken(User user, String token) {
        User byUsername = userRepository.findByUsername(user.getUsername());
        byUsername.setRefreshToken(token);
    }
}
