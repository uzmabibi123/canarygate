import { describe, expect, it } from "vitest";
import { buildIncidentCsv, findCorrelatedAlerts, filterIncidents, getIncidentMetrics, type CanaryIncident } from "./canarygate";

const incidents: CanaryIncident[] = [
  { id: 1, timestamp: "2026-09-25T12:00:00Z", sourceIp: "10.0.0.1", country: "Pakistan", incidentType: "CANARY_TRIGGERED", severity: "Critical", mitreTechnique: "T1078", details: "Decoy used", reviewStatus: "unreviewed" },
  { id: 2, timestamp: "2026-09-25T12:01:00Z", sourceIp: "10.0.0.1", country: "Pakistan", incidentType: "BLOCKED_HIGH_RISK", severity: "High", mitreTechnique: "T1190", details: "Payload blocked", reviewStatus: "confirmed" },
  { id: 3, timestamp: "2026-09-25T12:02:00Z", sourceIp: "10.0.0.1", country: "Pakistan", incidentType: "ALLOWED_WITH_WARNING", severity: "Medium", mitreTechnique: "T1071.001", details: "Review needed", reviewStatus: "false_positive" },
  { id: 4, timestamp: "2026-09-25T12:03:00Z", sourceIp: "10.0.0.2", country: "USA", incidentType: "BLOCKED_HIGH_RISK", severity: "High", mitreTechnique: "T1059", details: "Header injection blocked", reviewStatus: "unreviewed" },
];

describe("CanaryGate incident workflows", () => {
  it("calculates dashboard KPI counts from incident semantics", () => {
    expect(getIncidentMetrics(incidents)).toEqual({ total: 4, canary: 1, blocked: 2, warnings: 1, falsePositives: 1 });
  });

  it("correlates three alerts from the same source", () => {
    expect(findCorrelatedAlerts(incidents)).toEqual([{ sourceIp: "10.0.0.1", count: 3, country: "Pakistan" }]);
  });

  it("filters by search, event type, and severity", () => {
    expect(filterIncidents(incidents, "header", "All events", "All severities")).toHaveLength(1);
    expect(filterIncidents(incidents, "", "BLOCKED_HIGH_RISK", "High")).toHaveLength(2);
    expect(filterIncidents(incidents, "pakistan", "All events", "Critical")).toHaveLength(1);
  });

  it("exports review status and escapes commas safely in CSV", () => {
    const csv = buildIncidentCsv([{ ...incidents[0], details: "Decoy, used" }]);
    expect(csv).toContain("review_status");
    expect(csv).toContain('"Decoy, used"');
    expect(csv).toContain("unreviewed");
  });
});
