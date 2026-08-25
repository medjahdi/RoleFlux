"use client";

import { format, parseISO } from "date-fns";
import { AlertTriangle } from "lucide-react";
import { useFindings, Topbar, ErrorBar, LoadingScreen } from "../components/shared";

export default function AlertsPage() {
  const { data, loading, error, refreshing, lastUpdated, fetchData } = useFindings();

  if (loading && !data) return <LoadingScreen />;

  const alerts = data?.recent_findings?.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
  ) || [];

  return (
    <>
      <Topbar title="Alerts" subtitle="Critical & High severity" refreshing={refreshing} lastUpdated={lastUpdated} onRefresh={() => fetchData(true)} />
      <main className="content">
        <ErrorBar message={error} />

        {alerts.length === 0 && !error && (
          <div style={{ textAlign: "center", padding: "60px 20px", color: "var(--text-muted)" }}>
            <AlertTriangle size={32} style={{ marginBottom: 12, opacity: 0.4 }} />
            <p>No critical or high severity alerts found.</p>
          </div>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {alerts.map((f) => (
            <div key={f.id} className="panel" style={{ padding: 0 }}>
              <div style={{
                display: "flex", alignItems: "flex-start", gap: 16,
                padding: "16px 20px", borderLeft: `3px solid ${f.severity === "CRITICAL" ? "var(--sev-critical)" : "var(--sev-high)"}`,
              }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                    <span className={`chip chip-${f.severity.toLowerCase()}`}>{f.severity}</span>
                    <span style={{ fontSize: "0.7rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      {format(parseISO(f.timestamp), "MMM dd, yyyy · HH:mm:ss")}
                    </span>
                  </div>
                  <div style={{ fontSize: "0.88rem", color: "var(--text-primary)", lineHeight: 1.5, marginBottom: 8 }}>
                    {f.description}
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Risk Score</span>
                    <div style={{
                      width: 120, height: 4, background: "var(--surface-3)",
                      borderRadius: 2, overflow: "hidden",
                    }}>
                      <div style={{
                        height: "100%", borderRadius: 2,
                        width: `${f.risk_score}%`,
                        background: f.severity === "CRITICAL" ? "var(--sev-critical)" : "var(--sev-high)",
                      }} />
                    </div>
                    <span style={{
                      fontFamily: "var(--font-mono)", fontWeight: 600, fontSize: "0.82rem",
                      color: f.severity === "CRITICAL" ? "var(--sev-critical)" : "var(--sev-high)",
                    }}>
                      {f.risk_score}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </main>
    </>
  );
}
