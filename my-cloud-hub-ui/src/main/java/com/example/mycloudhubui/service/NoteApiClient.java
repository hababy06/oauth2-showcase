// my-cloud-hub-ui/src/main/java/com/example/mycloudhubui/service/NoteApiClient.java
package com.example.mycloudhubui.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class NoteApiClient {

    private final WebClient webClient;
    private final String NOTE_API_URL = "http://localhost:8081/api/notes";

    public Map<String, Object> getNotes() {
        try {
            // 使用配置好的 WebClient 發出 GET 請求
            // Access Token 會被自動加上
            return webClient.get()
                    .uri(NOTE_API_URL)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block(); // 在這個 BFF 場景中，使用 block() 簡化處理
        } catch (Exception e) {
            return Map.of("error", "無法獲取筆記列表: " + e.getMessage());
        }
    }
}