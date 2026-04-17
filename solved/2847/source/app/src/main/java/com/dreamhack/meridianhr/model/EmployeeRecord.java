package com.dreamhack.meridianhr.model;

public record EmployeeRecord(
        String id,
        String name,
        String department,
        String title,
        int score,
        String riskLevel,
        boolean promotionTrack,
        String manager,
        String focusTag) {
}
