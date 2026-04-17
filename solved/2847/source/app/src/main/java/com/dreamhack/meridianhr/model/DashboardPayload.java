package com.dreamhack.meridianhr.model;

import java.util.List;

public record DashboardPayload(
        List<MetricCard> metrics,
        List<EmployeeRecord> employees,
        List<ReviewTemplate> templates,
        List<NoticeEntry> notices,
        List<AuditEntry> audits) {
}
