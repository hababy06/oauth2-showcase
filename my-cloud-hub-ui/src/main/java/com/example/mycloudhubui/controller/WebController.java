package com.example.mycloudhubui.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {

    @GetMapping("/")
    public String index(Model model, @AuthenticationPrincipal OidcUser principal) {
        // 當使用者成功通過 OIDC 登入後，Spring Security 會自動注入一個 OidcUser 物件
        if (principal != null) {
            // 我們可以從 principal 物件中獲取 ID Token 中的 Claims (聲明)
            // 例如，獲取使用者的姓名並將其添加到 Model 中，以便在頁面上顯示

            // 嘗試獲取 'name' 或 'preferred_username' Claim
            String username = principal.getFullName();
            if (username == null) {
                username = principal.getPreferredUsername();
            }
            if (username == null) {
                username = principal.getSubject(); // 作為備用
            }

            model.addAttribute("username", username);
        }
        // 回傳 "index"，這會讓 Thymeleaf 去尋找名為 index.html 的模板
        return "index";
    }
}