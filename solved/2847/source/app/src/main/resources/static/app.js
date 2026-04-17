const elements = {
    metricsGrid: document.getElementById("metricsGrid"),
    employeeTableBody: document.getElementById("employeeTableBody"),
    departmentSelect: document.getElementById("departmentSelect"),
    searchInput: document.getElementById("searchInput"),
    templateSelect: document.getElementById("templateSelect"),
    focusInput: document.getElementById("focusInput"),
    previewForm: document.getElementById("previewForm"),
    previewTrace: document.getElementById("previewTrace"),
    previewOutput: document.getElementById("previewOutput"),
    previewChecks: document.getElementById("previewChecks"),
    noticesList: document.getElementById("noticesList"),
    auditsList: document.getElementById("auditsList")
};

const state = {
    templates: []
};

async function fetchJson(url, options = {}) {
    const response = await fetch(url, {
        headers: {
            "Content-Type": "application/json"
        },
        ...options
    });

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || "Request failed");
    }
    return data;
}

function renderMetrics(metrics) {
    elements.metricsGrid.innerHTML = metrics.map((metric) => `
        <article class="metric-card">
            <div class="metric-label">${metric.label}</div>
            <div class="metric-value">${metric.value}</div>
            <div class="metric-delta">${metric.delta}</div>
        </article>
    `).join("");
}

function renderEmployees(employees) {
    if (!employees.length) {
        elements.employeeTableBody.innerHTML = `
            <tr>
                <td colspan="5">
                    <div class="empty-state">No employees matched the current filters.</div>
                </td>
            </tr>
        `;
        return;
    }

    elements.employeeTableBody.innerHTML = employees.map((employee) => `
        <tr>
            <td>
                <div class="employee-name">${employee.name}</div>
                <div class="employee-meta">${employee.title} · ${employee.manager}</div>
            </td>
            <td>${employee.department}</td>
            <td>${employee.score}</td>
            <td><span class="risk-pill risk-${employee.riskLevel.toLowerCase()}">${employee.riskLevel}</span></td>
            <td><span class="track-pill">${employee.promotionTrack ? "Promotion" : "Watch"}</span></td>
        </tr>
    `).join("");
}

function populateDepartments(employees) {
    const departments = ["all", ...new Set(employees.map((employee) => employee.department))];
    elements.departmentSelect.innerHTML = departments.map((department) => `
        <option value="${department === "all" ? "all" : department}">${department === "all" ? "All departments" : department}</option>
    `).join("");
}

function renderTemplates(templates) {
    state.templates = templates;
    elements.templateSelect.innerHTML = templates.map((template) => `
        <option value="${template.id}">${template.label}</option>
    `).join("");

    if (templates.length) {
        elements.focusInput.placeholder = templates[0].analystHint;
    }
}

function renderStack(container, items, metaKey) {
    container.innerHTML = items.map((item) => `
        <article class="stack-item">
            <div class="stack-meta">
                <span class="stack-tag">${item[metaKey]}</span>
                ${item.time ? `<span class="stack-tag">${item.time}</span>` : ""}
            </div>
            <h4>${item.title}</h4>
            <p>${item.detail}</p>
        </article>
    `).join("");
}

async function loadDashboard() {
    const dashboard = await fetchJson("/api/dashboard", { method: "GET" });
    renderMetrics(dashboard.metrics);
    renderEmployees(dashboard.employees);
    populateDepartments(dashboard.employees);
    renderTemplates(dashboard.templates);
    renderStack(elements.noticesList, dashboard.notices, "tag");
    renderStack(elements.auditsList, dashboard.audits, "level");

    if (dashboard.templates.length) {
        elements.templateSelect.value = dashboard.templates[0].id;
        elements.focusInput.value = "manager discretion";
        await submitPreview();
    }
}

async function loadEmployees() {
    const params = new URLSearchParams();
    if (elements.searchInput.value.trim()) {
        params.set("q", elements.searchInput.value.trim());
    }
    if (elements.departmentSelect.value && elements.departmentSelect.value !== "all") {
        params.set("department", elements.departmentSelect.value);
    }

    const suffix = params.toString() ? `?${params.toString()}` : "";
    const employees = await fetchJson(`/api/employees${suffix}`, { method: "GET" });
    renderEmployees(employees);
}

async function submitPreview() {
    try {
        const payload = {
            templateId: elements.templateSelect.value,
            focus: elements.focusInput.value
        };

        const response = await fetchJson("/api/rules/preview", {
            method: "POST",
            body: JSON.stringify(payload)
        });

        elements.previewTrace.textContent = response.trace;
        elements.previewOutput.textContent = response.preview;
        elements.previewChecks.innerHTML = response.checks.map((check) => `<li>${check}</li>`).join("");
    } catch (error) {
        elements.previewTrace.textContent = "Preview rendering failed.";
        elements.previewOutput.textContent = error.message;
        elements.previewChecks.innerHTML = "";
    }
}

function bindEvents() {
    let employeeTimer;

    elements.searchInput.addEventListener("input", () => {
        window.clearTimeout(employeeTimer);
        employeeTimer = window.setTimeout(loadEmployees, 140);
    });

    elements.departmentSelect.addEventListener("change", loadEmployees);

    elements.templateSelect.addEventListener("change", () => {
        const template = state.templates.find((item) => item.id === elements.templateSelect.value);
        if (template) {
            elements.focusInput.placeholder = template.analystHint;
        }
    });

    elements.previewForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        await submitPreview();
    });
}

document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    await loadDashboard();
});
