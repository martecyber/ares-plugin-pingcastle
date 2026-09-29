package com.martecyber.plugins.pingcastle;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for PingCastle HTML report.
 * Extracts risk rules from the Active Directory health check report.
 */
@Component
public class PingCastleHTMLParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // PingCastle HTML risk rule sections contain class="rule-..." or data-risk
    private static final Pattern RULE_BLOCK = Pattern.compile(
        "<(?:div|tr)[^>]*class=\"[^\"]*rule[^\"]*\"[^>]*>(.*?)</(?:div|tr)>",
        Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern TITLE_PATTERN = Pattern.compile(
        "<h[2-4][^>]*>(.*?)</h[2-4]>|<td[^>]*class=\"[^\"]*title[^\"]*\"[^>]*>(.*?)</td>",
        Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern SCORE_PATTERN = Pattern.compile(
        "(?:Points?|Score)\\s*[=:]?\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_TAG = Pattern.compile("<[^>]+>");
    private static final Pattern SECTION_PATTERN = Pattern.compile(
        "<h[2-3][^>]*>([^<]+)</h[2-3]>", Pattern.CASE_INSENSITIVE);

    @Override public String getToolId() { return "pingcastle"; }
    @Override public String getDisplayName() { return "PingCastle HTML"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".html", ".htm"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8).toLowerCase();
        return s.contains("pingcastle") || (s.contains("active directory") && s.contains("risk"));
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        String html = new String(content, StandardCharsets.UTF_8);

        // Try to find risk rule blocks
        Matcher ruleMatcher = RULE_BLOCK.matcher(html);
        Set<String> seen = new HashSet<>();
        while (ruleMatcher.find()) {
            String block = ruleMatcher.group(1);
            processBlock(block, result, seen);
        }

        // Fallback: scan for any table rows referencing risk points
        if (result.getDetections().isEmpty()) {
            parseFallback(html, result, seen);
        }

        if (result.getDetections().isEmpty()) {
            result.addWarning("No risk rules extracted. Verify the PingCastle HTML report format.");
        }

        // Extract the AD domain name from the report and emit a directory asset
        String adDomain = extractAdDomain(html);
        if (adDomain != null) {
            result.addAsset(new ParsedAsset(adDomain, AssetType.DIRECTORY,
                Map.of("source", "pingcastle")));
            // Set the directory asset as detected_at for all detections that have no asset
            result.getDetections().stream()
                .filter(d -> d.getAssetIdentifier() == null)
                .forEach(d -> d.setAssetIdentifier(adDomain));
        }

        return result;
    }

    private void processBlock(String block, ParseResult result, Set<String> seen) {
        String text = HTML_TAG.matcher(block).replaceAll(" ").replaceAll("\\s+", " ").trim();
        if (text.length() < 10) return;

        // Try to extract title from heading
        Matcher titleMatcher = TITLE_PATTERN.matcher(block);
        String title = null;
        if (titleMatcher.find()) {
            title = HTML_TAG.matcher(titleMatcher.group(1) != null ? titleMatcher.group(1) : titleMatcher.group(2)).replaceAll("").trim();
        }
        if (title == null || title.length() < 5) {
            title = text.length() > 100 ? text.substring(0, 100) : text;
        }

        if (seen.contains(title)) return;
        seen.add(title);

        // Determine severity from score
        Matcher scoreMatcher = SCORE_PATTERN.matcher(text);
        int score = 0;
        if (scoreMatcher.find()) {
            try { score = Integer.parseInt(scoreMatcher.group(1)); } catch (Exception ignored) {}
        }
        String severity = scoreSeverity(score);

        String templateId = "pingcastle-" + title.toLowerCase().replaceAll("[^a-z0-9]+", "-");
        if (templateId.length() > 200) templateId = templateId.substring(0, 200);

        String raw;
        try { raw = MAPPER.writeValueAsString(Map.of("title", title, "score", score, "text", text.substring(0, Math.min(500, text.length())))); }
        catch (Exception e) { raw = "{}"; }

        result.addDetection(new ParsedDetection(title, severity,
            score > 0 ? "Risk points: " + score + "\n\n" + text : text, null, templateId, raw));
    }

    private void parseFallback(String html, ParseResult result, Set<String> seen) {
        // Look for risk point rows in any table: "<td>rule name</td><td>points</td>"
        Pattern rowPattern = Pattern.compile("<tr[^>]*>(.*?)</tr>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        Pattern tdPattern = Pattern.compile("<td[^>]*>(.*?)</td>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        Matcher rowMatcher = rowPattern.matcher(html);
        while (rowMatcher.find()) {
            String row = rowMatcher.group(1);
            List<String> cells = new ArrayList<>();
            Matcher tdMatcher = tdPattern.matcher(row);
            while (tdMatcher.find()) {
                cells.add(HTML_TAG.matcher(tdMatcher.group(1)).replaceAll("").trim());
            }
            if (cells.size() < 2) continue;
            String potentialScore = cells.get(cells.size() - 1);
            try {
                int score = Integer.parseInt(potentialScore.trim());
                if (score <= 0) continue;
                String name = cells.get(0);
                if (name.length() < 5 || seen.contains(name)) continue;
                seen.add(name);
                String severity = scoreSeverity(score);
                String templateId = "pingcastle-" + name.toLowerCase().replaceAll("[^a-z0-9]+", "-");
                if (templateId.length() > 200) templateId = templateId.substring(0, 200);
                String raw;
                try { raw = MAPPER.writeValueAsString(Map.of("name", name, "score", score)); } catch (Exception e) { raw = "{}"; }
                result.addDetection(new ParsedDetection(name, severity, "Risk points: " + score, null, templateId, raw));
            } catch (NumberFormatException ignored) {}
        }
    }

    private String scoreSeverity(int score) {
        if (score >= 20) return "critical";
        if (score >= 10) return "high";
        if (score >= 5) return "medium";
        return "low";
    }

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "(?:domain|domainname|Domain Name)[:\\s]+([a-zA-Z0-9][a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})",
        Pattern.CASE_INSENSITIVE);

    /** Tries to extract the AD domain name from the HTML report. */
    private String extractAdDomain(String html) {
        // PingCastle reports usually include the domain in a header or summary section
        Matcher m = DOMAIN_PATTERN.matcher(html);
        if (m.find()) return m.group(1).toLowerCase().trim();
        // Fallback: look for FQDN in title
        Matcher t = Pattern.compile("<title>[^<]*?([a-zA-Z0-9][a-zA-Z0-9-]*\\.[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})[^<]*?</title>",
            Pattern.CASE_INSENSITIVE).matcher(html);
        if (t.find()) return t.group(1).toLowerCase().trim();
        return null;
    }
}
