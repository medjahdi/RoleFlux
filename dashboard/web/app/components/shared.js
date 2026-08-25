"use client";

import { useState, useEffect, useCallback } from "react";
import { RefreshCw } from "lucide-react";
import { format } from "date-fns";

export function useFindings() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchData = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      const res = await fetch("/api/dashboard");
      if (!res.ok) throw new Error(`API returned ${res.status}`);
      const json = await res.json();
      setData(json);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => fetchData(), 20000);
    return () => clearInterval(interval);
  }, [fetchData]);

  return { data, loading, error, refreshing, lastUpdated, fetchData };
}

export function Topbar({ title, subtitle, refreshing, lastUpdated, onRefresh }) {
  return (
    <header className="topbar">
      <div className="topbar-left">
        {title} <span>/ {subtitle}</span>
      </div>
      <div className="topbar-right">
        {lastUpdated && (
          <span className="meta-time">
            Updated {format(lastUpdated, "HH:mm:ss")}
          </span>
        )}
        <button
          className={`btn-refresh${refreshing ? " spinning" : ""}`}
          onClick={onRefresh}
        >
          <RefreshCw size={13} />
          Refresh
        </button>
      </div>
    </header>
  );
}

export function ErrorBar({ message }) {
  if (!message) return null;
  return (
    <div className="error-bar">
      Connection failed: {message}
      <small>Ensure the FastAPI backend is running on port 8000</small>
    </div>
  );
}

export function LoadingScreen() {
  return (
    <div className="loading-screen">
      <div className="spinner" />
      <div className="loading-text">Connecting to RoleFlux engine...</div>
    </div>
  );
}
