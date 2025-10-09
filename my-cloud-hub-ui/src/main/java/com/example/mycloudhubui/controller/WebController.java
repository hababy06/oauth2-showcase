// my-cloud-hub-ui/src/main/java/com/example/mycloudhubui/controller/WebController.java
package com.example.mycloudhubui.controller;

import com.example.mycloudhubui.service.NoteApiClient;
import com.example.mycloudhubui.service.TaskApiClient;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

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
}