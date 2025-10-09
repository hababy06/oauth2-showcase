package com.example.noteservice.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;
import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/notes")
public class NoteController {

    @GetMapping
    public Map<String, Object> getNotes(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getSubject();
        // 從 JWT 的 claims 中讀取權限
        List<String> authorities = jwt.getClaimAsStringList("authorities");

        // ✨ 增加保護：如果 authorities 是 null，就給它一個空的列表
        if (authorities == null) {
            authorities = Collections.emptyList();
        }

        return Map.of(
                "notes", "這是 " + username + " 的筆記列表。",
                "authorities", authorities
        );
    }

    // 新增一個只有 ADMIN 角色才能訪問的端點
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')") // <-- 魔法發生的地方！
    public Map<String, String> deleteNote(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        String adminName = jwt.getSubject();
        return Map.of("message", "管理員 " + adminName + " 成功刪除了 ID 為 " + id + " 的筆記。");
    }
}