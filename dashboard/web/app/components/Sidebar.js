"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, LayoutDashboard, Bell, Activity, Settings,
} from "lucide-react";

import Image from "next/image";

const NAV = [
  { label: "Monitor", items: [
    { name: "Overview",      href: "/",         icon: LayoutDashboard },
    { name: "Alerts",        href: "/alerts",   icon: Bell },
    { name: "Activity Log",  href: "/activity", icon: Activity },
  ]},
  { label: "System", items: [
    { name: "Configuration", href: "/settings", icon: Settings },
  ]},
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="sidebar">
      <div className="sb-brand">
        <div className="sb-logo" style={{ background: "transparent", padding: 0 }}>
          <Image src="/logo.jpg" alt="RoleFlux Logo" width={28} height={28} style={{ borderRadius: 6 }} />
        </div>
        <div>
          <div className="sb-brand-name">RoleFlux</div>
          <div className="sb-brand-tag">v2.0 · Command Center</div>
        </div>
      </div>

      <nav className="sb-nav">
        {NAV.map((section) => (
          <div key={section.label}>
            <div className="sb-section-label">{section.label}</div>
            {section.items.map((item) => {
              const Icon = item.icon;
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`sb-item${active ? " active" : ""}`}
                >
                  <Icon size={17} />
                  {item.name}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sb-footer">
        <div className="sb-status">
          <div className="sb-dot" />
          Engine connected · us-central1
        </div>
      </div>
    </aside>
  );
}
