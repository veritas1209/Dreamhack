package com.dreamhack.meridianhr.service;

import com.dreamhack.meridianhr.model.ReviewTemplate;

public class PreviewEngine {

    public String compose(
            ReviewTemplate template,
            String cycleLabel,
            String priorityBand,
            Integer visibleCount,
            String focus) {
        String normalizedFocus = focus == null || focus.isBlank() ? "manager calibration drift" : focus.trim();

        return template.label()
                + " // "
                + cycleLabel
                + " // "
                + priorityBand
                + " // "
                + visibleCount
                + " visible records // focus="
                + normalizedFocus
                + " // policy="
                + template.policyLine();
    }
}
