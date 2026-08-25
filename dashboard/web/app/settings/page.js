"use client";

import { useFindings, Topbar, LoadingScreen } from "../components/shared";

const CONFIG_ITEMS = [
  { label: "Project ID", value: "roleflux-prod-1234" },
  { label: "Region", value: "us-central1" },
  { label: "Engine", value: "roleflux-engine (Cloud Function v2)" },
  { label: "Pub/Sub Topic", value: "roleflux-logs" },
  { label: "BigQuery Dataset", value: "roleflux_analytics.findings" },
  { label: "AI Model", value: "gemini-2.5-flash (Vertex AI)" },
  { label: "Slack Integration", value: "Enabled (Block Kit)" },
  { label: "Auto-Refresh", value: "Every 20 seconds" },
];

export default function SettingsPage() {
  const { refreshing, lastUpdated, fetchData } = useFindings();

  return (
    <>
      <Topbar title="Configuration" subtitle="System" refreshing={refreshing} lastUpdated={lastUpdated} onRefresh={() => fetchData(true)} />
      <main className="content">
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Infrastructure</span>
          </div>
          <div style={{ padding: 0 }}>
            {CONFIG_ITEMS.map((item, i) => (
              <div key={item.label} style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "12px 20px",
                borderBottom: i < CONFIG_ITEMS.length - 1 ? "1px solid var(--border-subtle)" : "none",
              }}>
                <span style={{ fontSize: "0.82rem", color: "var(--text-secondary)" }}>{item.label}</span>
                <span style={{
                  fontSize: "0.78rem", fontFamily: "var(--font-mono)",
                  color: "var(--text-primary)", background: "var(--surface-2)",
                  padding: "3px 10px", borderRadius: "var(--radius-sm)",
                }}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">
            <span className="panel-title">Detection Rules</span>
          </div>
          <div style={{ padding: 0 }}>
            {[
              { name: "IAM Policy Change", status: "Active", mitre: "T1098" },
              { name: "Public Bucket Exposure", status: "Active", mitre: "T1530" },
              { name: "Firewall Rule Anomaly", status: "Active", mitre: "T1562.007" },
              { name: "Crypto-Mining Detection", status: "Active", mitre: "T1496" },
              { name: "Service Account Abuse", status: "Active", mitre: "T1078.004" },
            ].map((rule, i) => (
              <div key={rule.name} style={{
                display: "flex", justifyContent: "space-between", alignItems: "center",
                padding: "12px 20px",
                borderBottom: i < 4 ? "1px solid var(--border-subtle)" : "none",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{
                    width: 6, height: 6, borderRadius: "50%",
                    background: "var(--accent)",
                  }} />
                  <span style={{ fontSize: "0.82rem", color: "var(--text-primary)" }}>{rule.name}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <span style={{
                    fontSize: "0.68rem", fontFamily: "var(--font-mono)",
                    color: "var(--text-muted)",
                  }}>
                    MITRE {rule.mitre}
                  </span>
                  <span style={{
                    fontSize: "0.66rem", fontWeight: 600,
                    color: "var(--accent)", background: "var(--accent-dim)",
                    padding: "2px 8px", borderRadius: 4,
                    textTransform: "uppercase", letterSpacing: "0.04em",
                  }}>
                    {rule.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </>
  );
}
