package com.dreamhack.meridianhr.model;

import java.util.List;

public record RulePreviewResponse(
        String templateId,
        String templateLabel,
        String preview,
        List<String> checks,
        String trace) {
}
