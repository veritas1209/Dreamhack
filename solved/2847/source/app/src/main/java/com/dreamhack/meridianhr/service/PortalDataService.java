package com.dreamhack.meridianhr.service;

import com.dreamhack.meridianhr.model.AuditEntry;
import com.dreamhack.meridianhr.model.DashboardPayload;
import com.dreamhack.meridianhr.model.EmployeeRecord;
import com.dreamhack.meridianhr.model.MetricCard;
import com.dreamhack.meridianhr.model.NoticeEntry;
import com.dreamhack.meridianhr.model.ReviewTemplate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class PortalDataService {

    private final List<EmployeeRecord> employees = List.of(
            new EmployeeRecord("E-104", "Mina Park", "Platform", "Senior Backend Engineer", 94, "Low", true, "R. Hwang", "promotion-readiness"),
            new EmployeeRecord("E-118", "Jae Oh", "Security", "Detection Engineer", 89, "Moderate", true, "N. Jang", "exceptions-watch"),
            new EmployeeRecord("E-133", "Ari Choi", "People Ops", "HRBP", 83, "Moderate", false, "V. Bell", "mobility-screen"),
            new EmployeeRecord("E-141", "Noah Kim", "Finance", "Comp Analyst", 78, "High", false, "T. Novak", "exceptions-watch"),
            new EmployeeRecord("E-155", "Dae Yun", "Platform", "Staff SRE", 96, "Low", true, "R. Hwang", "promotion-readiness"),
            new EmployeeRecord("E-166", "Yuna Seo", "Revenue", "Enterprise AE", 87, "Low", true, "P. Clay", "mobility-screen"),
            new EmployeeRecord("E-174", "Theo Lim", "Security", "AppSec Analyst", 91, "Moderate", true, "N. Jang", "promotion-readiness"),
            new EmployeeRecord("E-189", "Sora Han", "Design Ops", "Program Manager", 81, "Moderate", false, "V. Bell", "mobility-screen"));

    private final List<ReviewTemplate> templates = List.of(
            new ReviewTemplate(
                    "promotion-readiness",
                    "Promotion Readiness",
                    "Summarize how a candidate appears in the current calibration cycle.",
                    "Aurora",
                    "Escalate only when impact is durable across two review windows.",
                    "Try a label such as north cluster or manager discretion."),
            new ReviewTemplate(
                    "exceptions-watch",
                    "Exceptions Watch",
                    "Draft a cautionary note for analysts reviewing discretionary approvals.",
                    "Signal",
                    "Variance is acceptable only with board-aligned supporting evidence.",
                    "Highlight a segment like silent escalations or outlier approvals."),
            new ReviewTemplate(
                    "mobility-screen",
                    "Mobility Screen",
                    "Generate a quick note for lateral move candidates and retention risk.",
                    "Copper",
                    "Document business continuity before cross-functional transfers.",
                    "Use a focus like retention pressure or succession gap."));

    private final List<MetricCard> metrics = List.of(
            new MetricCard("Candidates In Scope", "48", "+6 from last week"),
            new MetricCard("Needs Board Review", "07", "2 locked packets"),
            new MetricCard("Median Readiness", "86", "steady in Q2"),
            new MetricCard("Risk Variance", "14%", "watch exceptions lane"));

    private final List<NoticeEntry> notices = List.of(
            new NoticeEntry("Cycle Freeze", "FY26 Q2 calibration notes lock on Friday 18:00 KST.", "Ops"),
            new NoticeEntry("Secure Attachments", "Sealed packets stay inside the executive locker path.", "Security"),
            new NoticeEntry("Preview Lab", "Analysts may test policy wording before attaching notes.", "Workflow"));

    private final List<AuditEntry> audits = List.of(
            new AuditEntry("Rule Studio", "Preview lab compiled 14 narrative drafts today.", "Info", "09:40"),
            new AuditEntry("Packet Locker", "Two executive packets remain sealed pending chair review.", "Restricted", "08:55"),
            new AuditEntry("Roster Sync", "Compensation snapshot imported from finance mirror.", "Info", "08:20"),
            new AuditEntry("Exception Lane", "Manual watchlist overrides require dual acknowledgement.", "Warning", "07:48"));

    private final Map<String, ReviewTemplate> templateMap = templates.stream()
            .collect(Collectors.toMap(ReviewTemplate::id, template -> template, (left, right) -> left, LinkedHashMap::new));

    public DashboardPayload dashboard() {
        return new DashboardPayload(metrics, employees, templates, notices, audits);
    }

    public List<EmployeeRecord> searchEmployees(String department, String query) {
        String normalizedDepartment = normalize(department);
        String normalizedQuery = normalize(query);

        return employees.stream()
                .filter(employee -> normalizedDepartment.isEmpty()
                        || "all".equals(normalizedDepartment)
                        || employee.department().toLowerCase(Locale.ROOT).equals(normalizedDepartment))
                .filter(employee -> normalizedQuery.isEmpty()
                        || employee.name().toLowerCase(Locale.ROOT).contains(normalizedQuery)
                        || employee.title().toLowerCase(Locale.ROOT).contains(normalizedQuery)
                        || employee.manager().toLowerCase(Locale.ROOT).contains(normalizedQuery))
                .toList();
    }

    public ReviewTemplate requireTemplate(String templateId) {
        ReviewTemplate template = templateMap.get(templateId);
        if (template == null) {
            throw new IllegalArgumentException("Unknown template requested.");
        }
        return template;
    }

    public Map<String, ReviewTemplate> templateMap() {
        return templateMap;
    }

    public PortalBindingRoot bindingRoot(String flag) {
        return new PortalBindingRoot(employees, flag);
    }

    private String normalize(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
