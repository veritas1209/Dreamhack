package com.dreamhack.meridianhr.service;

public class ReviewPacket {

    private final String reference;
    private final String referenceToken;
    private final String summary;

    public ReviewPacket(String reference, String referenceToken, String summary) {
        this.reference = reference;
        this.referenceToken = referenceToken;
        this.summary = summary;
    }

    public String getReference() {
        return reference;
    }

    public String getReferenceToken() {
        return referenceToken;
    }

    public String getSummary() {
        return summary;
    }
}
