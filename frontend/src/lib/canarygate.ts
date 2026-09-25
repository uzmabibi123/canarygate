export type CanarySeverity = "Low" | "Medium" | "High" | "Critical";
export type CanaryReviewStatus = "unreviewed" | "confirmed" | "false_positive";

export type CanaryIncident = {
  id: number;
  timestamp: string;
  sourceIp: string;
  country: string;
  incidentType: string;
  severity: CanarySeverity;
  mitreTechnique: string;
  details: string;
  reviewStatus: CanaryReviewStatus;
};

export function getIncidentMetrics(incidents: CanaryIncident[]) {
  return {
    total: incidents.length,
    canary: incidents.filter((item) => item.incidentType === "CANARY_TRIGGERED").length,
    blocked: incidents.filter((item) => item.incidentType === "BLOCKED_HIGH_RISK").length,
    warnings: incidents.filter((item) => item.incidentType === "ALLOWED_WITH_WARNING").length,
    falsePositives: incidents.filter((item) => item.reviewStatus === "false_positive").length,
  };
}

export function findCorrelatedAlerts(incidents: CanaryIncident[], minimum = 3) {
  const grouped = incidents.reduce<Record<string, CanaryIncident[]>>((groups, incident) => {
    (groups[incident.sourceIp] ||= []).push(incident);
    return groups;
  }, {});
  return Object.entries(grouped)
    .filter(([, group]) => group.length >= minimum)
    .map(([sourceIp, group]) => ({ sourceIp, count: group.length, country: group[0].country }));
}

export function filterIncidents(incidents: CanaryIncident[], query: string, type: string, severity: string) {
  const normalized = query.trim().toLowerCase();
  return incidents.filter((incident) => {
    const matchesQuery = !normalized || [incident.sourceIp, incident.country, incident.incidentType, incident.details, incident.mitreTechnique].join(" ").toLowerCase().includes(normalized);
    const matchesType = type === "All events" || incident.incidentType === type;
    const matchesSeverity = severity === "All severities" || incident.severity === severity;
    return matchesQuery && matchesType && matchesSeverity;
  });
}

export function buildIncidentCsv(incidents: CanaryIncident[]) {
  const header = "id,timestamp,source_ip,country,incident_type,severity,mitre_technique,review_status,details";
  const rows = incidents.map((item) => [item.id, item.timestamp, item.sourceIp, item.country, item.incidentType, item.severity, item.mitreTechnique, item.reviewStatus, `"${item.details.replaceAll('"', '""')}"`].join(","));
  return [header, ...rows].join("\n");
}
