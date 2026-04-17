package com.dreamhack.meridianhr.service;

import com.dreamhack.meridianhr.model.EmployeeRecord;
import java.util.List;

public class DirectoryLens {

    private final int visibleCount;
    private final List<EmployeeRecord> visibleEmployees;

    public DirectoryLens(List<EmployeeRecord> visibleEmployees) {
        this.visibleEmployees = List.copyOf(visibleEmployees);
        this.visibleCount = visibleEmployees.size();
    }

    public int getVisibleCount() {
        return visibleCount;
    }

    public List<EmployeeRecord> getVisibleEmployees() {
        return visibleEmployees;
    }
}
