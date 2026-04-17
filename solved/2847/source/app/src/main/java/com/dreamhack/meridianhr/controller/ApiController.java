package com.dreamhack.meridianhr.controller;

import com.dreamhack.meridianhr.model.DashboardPayload;
import com.dreamhack.meridianhr.model.EmployeeRecord;
import com.dreamhack.meridianhr.model.RulePreviewRequest;
import com.dreamhack.meridianhr.model.RulePreviewResponse;
import com.dreamhack.meridianhr.service.PortalDataService;
import com.dreamhack.meridianhr.service.RulePreviewService;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final PortalDataService portalDataService;
    private final RulePreviewService rulePreviewService;

    public ApiController(PortalDataService portalDataService, RulePreviewService rulePreviewService) {
        this.portalDataService = portalDataService;
        this.rulePreviewService = rulePreviewService;
    }

    @GetMapping("/dashboard")
    public DashboardPayload dashboard() {
        return portalDataService.dashboard();
    }

    @GetMapping("/employees")
    public List<EmployeeRecord> employees(
            @RequestParam(required = false) String department,
            @RequestParam(required = false, name = "q") String query) {
        return portalDataService.searchEmployees(department, query);
    }

    @PostMapping("/rules/preview")
    public ResponseEntity<?> preview(@RequestBody RulePreviewRequest request) {
        try {
            RulePreviewResponse response = rulePreviewService.preview(request);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException exception) {
            return ResponseEntity.badRequest().body(Map.of("error", exception.getMessage()));
        }
    }
}
