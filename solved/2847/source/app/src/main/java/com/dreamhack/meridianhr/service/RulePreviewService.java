package com.dreamhack.meridianhr.service;

import com.dreamhack.meridianhr.model.ReviewTemplate;
import com.dreamhack.meridianhr.model.RulePreviewRequest;
import com.dreamhack.meridianhr.model.RulePreviewResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import ognl.Ognl;
import ognl.OgnlException;
import org.springframework.stereotype.Service;

@Service
public class RulePreviewService {

    private final PortalDataService portalDataService;

    public RulePreviewService(PortalDataService portalDataService) {
        this.portalDataService = portalDataService;
    }

    public RulePreviewResponse preview(RulePreviewRequest request) {
        if (request == null || request.templateId() == null || request.templateId().isBlank()) {
            throw new IllegalArgumentException("Choose a template before rendering the preview.");
        }

        ReviewTemplate template = portalDataService.requireTemplate(request.templateId());
        String focus = sanitizeFocus(request.focus());
        PortalBindingRoot root = portalDataService.bindingRoot(resolveFlag());

        try {
            Map<String, Object> context = Ognl.createDefaultContext(root);
            context.put("templates", portalDataService.templateMap());

            String expression = "previewEngine.compose(#templates['"
                    + template.id()
                    + "'], cycle.label, insightDeck.priorityBand, directory.visibleCount, '"
                    + focus
                    + "')";

            Object parsed = Ognl.parseExpression(expression);
            Object rendered = Ognl.getValue(parsed, context, root);

            return new RulePreviewResponse(
                    template.id(),
                    template.label(),
                    String.valueOf(rendered),
                    List.of(
                            "Cycle binding: " + root.getCycle().getLabel(),
                            "Priority band: " + root.getInsightDeck().getPriorityBand(),
                            "Visible roster: " + root.getDirectory().getVisibleCount(),
                            "Template accent: " + template.accent()),
                    "Policy lab compiled the catalog entry, live cycle state, directory lens, and analyst focus into one preview path.");
        } catch (OgnlException exception) {
            throw new IllegalArgumentException("Preview rendering failed. Review the focus label format.");
        }
    }

    private String resolveFlag() {
        return Optional.ofNullable(System.getenv("CHALLENGE_FLAG"))
                .filter(value -> !value.isBlank())
                .orElse("DH{development_only_replace_me}");
    }

    private String sanitizeFocus(String focus) {
        if (focus == null) {
            return "";
        }

        return focus.replace('\r', ' ')
                .replace('\n', ' ')
                .trim();
    }
}
