package com.dreamhack.meridianhr.service;

public class ReviewCycle {

    private final String label;
    private final String lane;
    private final String lockDate;

    public ReviewCycle(String label, String lane, String lockDate) {
        this.label = label;
        this.lane = lane;
        this.lockDate = lockDate;
    }

    public String getLabel() {
        return label;
    }

    public String getLane() {
        return lane;
    }

    public String getLockDate() {
        return lockDate;
    }
}
