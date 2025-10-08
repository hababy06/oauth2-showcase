package com.example.noteservice.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api/notes")
public class NoteController {

    @GetMapping
    public Map<String, Object> getNotes(@AuthenticationPrincipal Jwt jwt) {
        // @AuthenticationPrincipal Jwt 可以直接注入解碼後的 JWT 物件
        // 我們可以從中獲取使用者名稱 (sub claim)
        String username = jwt.getSubject();
        return Collections.singletonMap("notes", "這是 " + username + " 的筆記列表。");
    }
}