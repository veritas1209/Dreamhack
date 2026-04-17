package com.dreamhack.meridianhr.service;

import com.dreamhack.meridianhr.model.EmployeeRecord;
import java.util.List;

public class PortalBindingRoot {

    private final PreviewEngine previewEngine;
    private final ReviewCycle cycle;
    private final InsightDeck insightDeck;
    private final DirectoryLens directory;
    private final ExecutiveReviewBoard board;

    public PortalBindingRoot(List<EmployeeRecord> employees, String flag) {
        this.previewEngine = new PreviewEngine();
        this.cycle = new ReviewCycle("FY26 Q2 Calibration", "manager-review", "Apr 12 lock");
        this.insightDeck = new InsightDeck("Tier-2 exception lane", "manager discretion", "policy-lab");
        this.directory = new DirectoryLens(employees);
        this.board = new ExecutiveReviewBoard(flag);
    }

    public PreviewEngine getPreviewEngine() {
        return previewEngine;
    }

    public ReviewCycle getCycle() {
        return cycle;
    }

    public InsightDeck getInsightDeck() {
        return insightDeck;
    }

    public DirectoryLens getDirectory() {
        return directory;
    }

    public ExecutiveReviewBoard getBoard() {
        return board;
    }
}
