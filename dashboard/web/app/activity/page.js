"use client";

import { format, parseISO } from "date-fns";
import { useFindings, Topbar, ErrorBar, LoadingScreen } from "../components/shared";

export default function ActivityPage() {
  const { data, loading, error, refreshing, lastUpdated, fetchData } = useFindings();

  if (loading && !data) return <LoadingScreen />;

  const findings = data?.recent_findings || [];

  return (
    <>
      <Topbar title="Activity Log" subtitle="All events" refreshing={refreshing} lastUpdated={lastUpdated} onRefresh={() => fetchData(true)} />
      <main className="content">
        <ErrorBar message={error} />

        <div style={{ display: "flex", flexDirection: "column", gap: 0 }}>
          {findings.map((f, i) => (
            <div key={f.id} style={{
              display: "flex", alignItems: "flex-start", gap: 16,
              padding: "14px 0",
              borderBottom: i < findings.length - 1 ? "1px solid var(--border-subtle)" : "none",
            }}>
              {/* Timeline dot */}
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 4 }}>
                <div style={{
                  width: 8, height: 8, borderRadius: "50%",
                  background: f.severity === "CRITICAL" ? "var(--sev-critical)" :
                    f.severity === "HIGH" ? "var(--sev-high)" :
                    f.severity === "MEDIUM" ? "var(--sev-medium)" : "var(--sev-low)",
                  flexShrink: 0,
                }} />
              </div>

              {/* Content */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                  <span className={`chip chip-${f.severity.toLowerCase()}`}>{f.severity}</span>
                  <span style={{
                    fontFamily: "var(--font-mono)", fontSize: "0.68rem",
                    color: "var(--text-muted)",
                  }}>
                    score {f.risk_score}
                  </span>
                </div>
                <div style={{ fontSize: "0.82rem", color: "var(--text-primary)", lineHeight: 1.5 }}>
                  {f.description}
                </div>
              </div>

              {/* Timestamp */}
              <div style={{
                fontFamily: "var(--font-mono)", fontSize: "0.68rem",
                color: "var(--text-muted)", whiteSpace: "nowrap", paddingTop: 4,
              }}>
                {format(parseISO(f.timestamp), "MMM dd, HH:mm")}
              </div>
            </div>
          ))}
        </div>
      </main>
    </>
  );
}
