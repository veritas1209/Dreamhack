package com.dreamhack.meridianhr.service;

public class InsightDeck {

    private final String priorityBand;
    private final String defaultFocus;
    private final String traceLabel;

    public InsightDeck(String priorityBand, String defaultFocus, String traceLabel) {
        this.priorityBand = priorityBand;
        this.defaultFocus = defaultFocus;
        this.traceLabel = traceLabel;
    }

    public String getPriorityBand() {
        return priorityBand;
    }

    public String getDefaultFocus() {
        return defaultFocus;
    }

    public String getTraceLabel() {
        return traceLabel;
    }
}
