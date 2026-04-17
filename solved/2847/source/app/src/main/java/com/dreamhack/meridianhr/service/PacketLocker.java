package com.dreamhack.meridianhr.service;

public class PacketLocker {

    private final String lockerId;
    private final ReviewPacket activePacket;

    public PacketLocker(String flag) {
        this.lockerId = "CAB-4B";
        this.activePacket = new ReviewPacket(
                "fy26-q2-sealed",
                flag,
                "Restricted packet for executive calibration only.");
    }

    public String getLockerId() {
        return lockerId;
    }

    public ReviewPacket getActivePacket() {
        return activePacket;
    }
}
