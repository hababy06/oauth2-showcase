// my-cloud-hub-ui/src/main/java/com/example/mycloudhubui/service/TaskApiClient.java
package com.example.mycloudhubui.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class TaskApiClient {

    private final WebClient webClient;
    private final String TASK_API_URL = "http://localhost:8082/api/tasks";

    public Map<String, Object> getTasks() {
        try {
            return webClient.get()
                    .uri(TASK_API_URL)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();
        } catch (Exception e) {
            return Map.of("error", "無法獲取任務列表: " + e.getMessage());
        }
    }
}