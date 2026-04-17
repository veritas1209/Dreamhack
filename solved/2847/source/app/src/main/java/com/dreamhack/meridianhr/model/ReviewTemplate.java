package com.dreamhack.meridianhr.model;

public record ReviewTemplate(
        String id,
        String label,
        String summary,
        String accent,
        String policyLine,
        String analystHint) {
}
