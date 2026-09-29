package com.martecyber.plugins.pingcastle;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link PingCastleHTMLParser}'s two-tier heuristic extraction: rule blocks explicitly
 *  classed {@code rule-*} (primary), a generic risk-points table-row scan used only when the
 *  primary pass finds nothing, per-score severity bucketing, the AD-domain backfill onto every
 *  detection left without an asset, and per-title dedup within one report. */
class PingCastleHTMLParserTest {

    private final PingCastleHTMLParser parser = new PingCastleHTMLParser();

    private ParseResult parse(String html) throws Exception {
        return parser.parse(html.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresPingcastleOrActiveDirectoryPlusRisk() {
        assertTrue(parser.validate("<html>PingCastle report</html>".getBytes(StandardCharsets.UTF_8)));
        assertTrue(parser.validate("<html>Active Directory Risk assessment</html>".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("<html>Unrelated report</html>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void extractsARuleBlockWithItsHeadingTitleAndScoredSeverity() throws Exception {
        String html = "<html><body>"
            + "<div class=\"rule-critical-item\">"
            + "<h3>Weak password policy</h3>"
            + "<p>Points: 25</p>"
            + "<p>Detailed description of the weak password policy issue.</p>"
            + "</div>"
            + "</body></html>";
        ParseResult result = parse(html);

        ParsedDetection d = result.getDetections().get(0);
        assertEquals("Weak password policy", d.getTitle());
        assertEquals("critical", d.getSeverity());
        assertTrue(d.getDescription().contains("Risk points: 25"));
        assertEquals("pingcastle-weak-password-policy", d.getSourceTemplateId());
    }

    @Test
    void severityBucketsFollowThePingCastlePointsScale() throws Exception {
        String html = "<html><body>"
            + "<div class=\"rule-x\"><h3>Rule A very long enough name</h3><p>Score: 20</p></div>"
            + "<div class=\"rule-x\"><h3>Rule B very long enough name</h3><p>Score: 10</p></div>"
            + "<div class=\"rule-x\"><h3>Rule C very long enough name</h3><p>Score: 5</p></div>"
            + "<div class=\"rule-x\"><h3>Rule D very long enough name</h3><p>Score: 1</p></div>"
            + "</body></html>";
        var detections = parse(html).getDetections();
        assertEquals("critical", detections.get(0).getSeverity());
        assertEquals("high",     detections.get(1).getSeverity());
        assertEquals("medium",   detections.get(2).getSeverity());
        assertEquals("low",      detections.get(3).getSeverity());
    }

    @Test
    void ruleBlockWithoutAHeadingFallsBackToTruncatedFlattenedText() throws Exception {
        String html = "<html><body>"
            + "<div class=\"rule-x\">Some free-form risk description with no heading at all, quite long.</div>"
            + "</body></html>";
        ParsedDetection d = parse(html).getDetections().get(0);
        assertTrue(d.getTitle().startsWith("Some free-form risk description"));
    }

    @Test
    void duplicateTitlesWithinTheSameReportAreOnlyReportedOnce() throws Exception {
        String html = "<html><body>"
            + "<div class=\"rule-x\"><h3>Repeated rule name</h3><p>Score: 10</p></div>"
            + "<div class=\"rule-y\"><h3>Repeated rule name</h3><p>Score: 10</p></div>"
            + "</body></html>";
        assertEquals(1, parse(html).getDetections().size());
    }

    @Test
    void adDomainIsExtractedAndBackfilledOntoDetectionsWithoutAnAsset() throws Exception {
        String html = "<html><body>"
            + "<p>Domain Name: corp.example.com</p>"
            + "<div class=\"rule-x\"><h3>Weak password policy</h3><p>Score: 10</p></div>"
            + "</body></html>";
        ParseResult result = parse(html);

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DIRECTORY) && a.getIdentifier().equals("corp.example.com")));
        assertEquals("corp.example.com", result.getDetections().get(0).getAssetIdentifier());
    }

    @Test
    void fallsBackToATableRowScanOnlyWhenNoRuleBlocksMatched() throws Exception {
        // No class="rule-*" anywhere — the primary pass finds nothing, so the generic
        // "<td>name</td><td>points</td>" scan takes over. A zero-score row is skipped.
        String html = "<html><body><table>"
            + "<tr><td>Weak password policy</td><td>25</td></tr>"
            + "<tr><td>Non-issue</td><td>0</td></tr>"
            + "</table></body></html>";
        ParseResult result = parse(html);

        assertEquals(1, result.getDetections().size());
        ParsedDetection d = result.getDetections().get(0);
        assertEquals("Weak password policy", d.getTitle());
        assertEquals("critical", d.getSeverity());
    }

    @Test
    void reportWithNothingExtractableProducesAWarning() throws Exception {
        ParseResult result = parse("<html><body>PingCastle report with no rules or tables.</body></html>");
        assertTrue(result.getDetections().isEmpty());
        assertFalse(result.getWarnings().isEmpty());
    }
}
