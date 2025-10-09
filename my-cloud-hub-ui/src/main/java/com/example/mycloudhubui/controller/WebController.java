// my-cloud-hub-ui/src/main/java/com/example/mycloudhubui/controller/WebController.java
package com.example.mycloudhubui.controller;

import com.example.mycloudhubui.service.NoteApiClient;
import com.example.mycloudhubui.service.TaskApiClient;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.web.csrf.CsrfToken;
import java.util.Map;

@Controller
@RequiredArgsConstructor
public class WebController {

    private final NoteApiClient noteApiClient;
    private final TaskApiClient taskApiClient;

    @GetMapping("/")
    public String index(Model model, @AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            String username = principal.getFullName();
            if (username == null) {
                username = principal.getPreferredUsername();
            }
            if (username == null) {
                username = principal.getSubject();
            }
            model.addAttribute("username", username);

            // --- ✨ 新增的程式碼 ---
            // 呼叫後端 API 並將結果加入 Model
            model.addAttribute("notesResponse", noteApiClient.getNotes());
            model.addAttribute("tasksResponse", taskApiClient.getTasks());
            // --- ✨ 新增結束 ---
        }
        return "index";
    }

    @DeleteMapping("/api/notes/{id}")
    @ResponseBody
    public ResponseEntity<Map<String, String>> deleteNote(
            @PathVariable String id,
            @RequestHeader(name = "X-CSRF-TOKEN", required = false) String headerToken,
            HttpServletRequest request) {

        // --- START: 診斷日誌 ---
        // Spring Security 會將它期望在 Session 中看到的 Token 放到請求的一個屬性裡
        CsrfToken sessionToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        System.out.println();
        System.out.println("========== CSRF Token 診斷日誌 ==========");
        System.out.println("來自瀏覽器 Header 的 Token: " + headerToken);

        if (sessionToken != null) {
            System.out.println("伺服器 Session 期望的 Token: " + sessionToken.getToken());
            boolean isMatch = sessionToken.getToken().equals(headerToken);
            System.out.println("兩者是否匹配? " + isMatch);
        } else {
            System.out.println("伺服器 Session 期望的 Token: 找不到！");
        }
        System.out.println("==========================================");
        System.out.println();
        // --- END: 診斷日誌 ---

        // 注意：即使 Token 不匹配，安全過濾器也會先回傳 403，所以下面的業務邏輯可能不會執行到
        // 但這些日誌能幫助我們確認問題。
        try {
            Map<String, String> response = noteApiClient.deleteNoteById(id);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }
}