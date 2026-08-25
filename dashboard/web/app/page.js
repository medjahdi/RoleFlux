"use client";

import { useState, Fragment } from "react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from "recharts";
import { format, parseISO } from "date-fns";
import { ChevronDown, ChevronRight } from "lucide-react";
import { useFindings, Topbar, ErrorBar, LoadingScreen } from "./components/shared";

function scoreColor(score) {
  if (score >= 90) return "var(--sev-critical)";
  if (score >= 70) return "var(--sev-high)";
  if (score >= 40) return "var(--sev-medium)";
  return "var(--sev-low)";
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: "var(--surface-2)", border: "1px solid var(--border-default)",
      borderRadius: "var(--radius-sm)", padding: "8px 12px", fontSize: "0.75rem",
    }}>
      <div style={{ color: "var(--text-muted)", marginBottom: 4 }}>{label}</div>
      <div style={{ color: "var(--accent)", fontWeight: 600, fontFamily: "var(--font-mono)" }}>
        Risk Score: {payload[0].value}
      </div>
    </div>
  );
}

export default function OverviewPage() {
  const { data, loading, error, refreshing, lastUpdated, fetchData } = useFindings();
  const [expandedRow, setExpandedRow] = useState(null);

  if (loading && !data) return <LoadingScreen />;

  const chartData = [];
  if (data?.recent_findings) {
    [...data.recent_findings].reverse().forEach((f) => {
      chartData.push({
        time: format(parseISO(f.timestamp), "HH:mm"),
        risk: f.risk_score,
      });
    });
  }

  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  data?.recent_findings?.forEach((f) => {
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  });
  const total = data?.total_events || 1;

  return (
    <>
      <Topbar title="Overview" subtitle="Dashboard" refreshing={refreshing} lastUpdated={lastUpdated} onRefresh={() => fetchData(true)} />
      <main className="content">
        <ErrorBar message={error} />
        {data && (
          <>
            {/* KPI Strip */}
            <div className="kpi-strip">
              <div className="kpi">
                <div className="kpi-bar" style={{ background: "var(--accent)" }} />
                <div className="kpi-label">Total Events</div>
                <div className="kpi-value">{data.total_events}</div>
                <div className="kpi-sub">last 50 ingested</div>
              </div>
              <div className="kpi">
                <div className="kpi-bar" style={{ background: "var(--sev-critical)" }} />
                <div className="kpi-label">Critical Threats</div>
                <div className="kpi-value v-crit">{data.critical_events}</div>
                <div className="kpi-sub">requires attention</div>
              </div>
              <div className="kpi">
                <div className="kpi-bar" style={{ background: "var(--sev-high)" }} />
                <div className="kpi-label">Avg Risk Score</div>
                <div className="kpi-value v-warn">{data.avg_score}</div>
                <div className="kpi-sub">across all events</div>
              </div>
              <div className="kpi">
                <div className="kpi-bar" style={{ background: "var(--accent)" }} />
                <div className="kpi-label">Detection Rate</div>
                <div className="kpi-value v-accent">
                  {total > 0 ? Math.round(((sevCounts.CRITICAL + sevCounts.HIGH) / total) * 100) : 0}%
                </div>
                <div className="kpi-sub">high+ severity ratio</div>
              </div>
            </div>

            {/* Chart + Breakdown */}
            <div className="dash-grid">
              <div className="panel">
                <div className="panel-head">
                  <span className="panel-title">Threat Activity</span>
                  <span style={{ fontSize: "0.68rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>risk score / event</span>
                </div>
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                      <defs>
                        <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.25} />
                          <stop offset="100%" stopColor="var(--accent)" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                      <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} fontFamily="var(--font-mono)" />
                      <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} fontFamily="var(--font-mono)" domain={[0, 100]} />
                      <Tooltip content={<ChartTooltip />} />
                      <Area type="monotone" dataKey="risk" stroke="var(--accent)" strokeWidth={2} fillOpacity={1} fill="url(#grad)" dot={false} activeDot={{ r: 4, fill: "var(--accent)", strokeWidth: 0 }} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="panel">
                <div className="panel-head">
                  <span className="panel-title">Severity Breakdown</span>
                </div>
                <div className="sev-breakdown">
                  {[
                    { name: "Critical", key: "CRITICAL", color: "var(--sev-critical)" },
                    { name: "High", key: "HIGH", color: "var(--sev-high)" },
                    { name: "Medium", key: "MEDIUM", color: "var(--sev-medium)" },
                    { name: "Low", key: "LOW", color: "var(--sev-low)" },
                    { name: "Info", key: "INFO", color: "var(--sev-info)" },
                  ].map((s) => (
                    <div className="sev-row" key={s.key}>
                      <div className="sev-row-top">
                        <div className="sev-row-left">
                          <div className="sev-dot" style={{ background: s.color }} />
                          <span className="sev-name">{s.name}</span>
                        </div>
                        <span className="sev-count">{sevCounts[s.key] || 0}</span>
                      </div>
                      <div className="sev-track">
                        <div className="sev-fill" style={{ width: `${total > 0 ? ((sevCounts[s.key] || 0) / total) * 100 : 0}%`, background: s.color }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Findings Table */}
            <div className="tbl-panel">
              <div className="panel-head">
                <span className="panel-title">Recent Findings</span>
                <span style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>{data.recent_findings.length} events</span>
              </div>
              <div className="tbl-scroll">
                <table className="findings">
                  <thead>
                    <tr>
                      <th style={{ width: 150 }}>Timestamp</th>
                      <th style={{ width: 100 }}>Severity</th>
                      <th style={{ width: 100 }}>Score</th>
                      <th>Description</th>
                      <th style={{ width: 40 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_findings.map((f) => (
                      <Fragment key={f.id}>
                        <tr onClick={() => setExpandedRow(expandedRow === f.id ? null : f.id)}>
                          <td className="cell-ts">{format(parseISO(f.timestamp), "MMM dd, HH:mm:ss")}</td>
                          <td><span className={`chip chip-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                          <td>
                            <div className="score-bar-wrap">
                              <span className="cell-score" style={{ color: scoreColor(f.risk_score) }}>{f.risk_score}</span>
                              <div className="score-bar"><div className="score-bar-inner" style={{ width: `${f.risk_score}%`, background: scoreColor(f.risk_score) }} /></div>
                            </div>
                          </td>
                          <td className="cell-desc">{f.description}</td>
                          <td style={{ textAlign: "center" }}>
                            {expandedRow === f.id ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}
                          </td>
                        </tr>
                        {expandedRow === f.id && (
                          <tr className="expanded-row">
                            <td colSpan={5}>
                              <div className="expand-inner">
                                <div className="expand-grid">
                                  <div className="expand-card">
                                    <div className="expand-card-title">Event Details</div>
                                    <p><strong>Severity:</strong> {f.severity}<br /><strong>Risk Score:</strong> {f.risk_score}/100<br /><strong>Timestamp:</strong> {format(parseISO(f.timestamp), "PPpp")}</p>
                                  </div>
                                  <div className="expand-card">
                                    <div className="expand-card-title">Description</div>
                                    <p>{f.description}</p>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </main>
    </>
  );
}
