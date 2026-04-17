package com.dreamhack.meridianhr.service;

public class ExecutiveReviewBoard {

    private final String chair;
    private final String channel;
    private final PacketLocker packetLocker;

    public ExecutiveReviewBoard(String flag) {
        this.chair = "S. Ivers";
        this.channel = "sealed-board";
        this.packetLocker = new PacketLocker(flag);
    }

    public String getChair() {
        return chair;
    }

    public String getChannel() {
        return channel;
    }

    public PacketLocker getPacketLocker() {
        return packetLocker;
    }
}
