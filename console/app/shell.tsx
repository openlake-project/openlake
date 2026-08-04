"use client";

import { type ReactNode } from "react";
import { Cpu, LayoutDashboard, Moon, Server, Sun } from "lucide-react";

type ActiveRoute = "dashboard" | "nodes" | "fleet";

const navigation = [
  { id: "dashboard" as const, href: "/", label: "Dashboard", Icon: LayoutDashboard },
  { id: "nodes" as const, href: "/nodes", label: "Topology", Icon: Cpu },
  { id: "fleet" as const, href: "/fleet", label: "Fleet", Icon: Server },
];

function Header({ active, onTheme }: { active: ActiveRoute; onTheme: () => void }) {
  return <header className="topbar">
    <nav className="topbar-nav" aria-label="Primary navigation">
      {navigation.map(({ id, href, label, Icon }) => <a href={href} className={active === id ? "active" : undefined} aria-current={active === id ? "page" : undefined} key={id}><Icon size={15}/><span>{label}</span></a>)}
    </nav>
    <button className="header-icon" onClick={onTheme} aria-label="Toggle color theme"><Sun className="theme-icon theme-icon-sun" size={17}/><Moon className="theme-icon theme-icon-moon" size={17}/></button>
  </header>;
}

export function AppShell({ active, children, mainClassName, showFooter = true }: { active: ActiveRoute; children: ReactNode; mainClassName?: string; showFooter?: boolean }) {
  const changeTheme = () => {
    const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
    const next = current === "dark" ? "light" : "dark";
    localStorage.setItem("openlake-theme", next);
    document.documentElement.dataset.theme = next;
  };

  return <div className={`app-shell view-overview view-${active}`}>
    <div className="app-main">
      <Header active={active} onTheme={changeTheme}/>
      <main className={mainClassName}>
        {children}
        {showFooter ? <footer className="page-footer"><span>OpenLake Control Plane</span></footer> : null}
      </main>
    </div>
  </div>;
}
