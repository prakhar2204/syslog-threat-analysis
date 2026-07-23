/* SysLog Threat Analysis — Sidebar Navigation (Phase 5.6) */

import { NavLink } from 'react-router-dom';
import { LayoutDashboard, ScrollText, AlertTriangle, Crosshair, FileDown, Settings, Upload } from 'lucide-react';

const NAV = [
  { to: '/',          icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/incidents', icon: AlertTriangle,   label: 'Incidents'  },
  { to: '/logs',      icon: ScrollText,      label: 'Logs'       },
  { to: '/upload',    icon: Upload,          label: 'Investigate'},
  { to: '/simulator', icon: Crosshair,       label: 'Simulator'  },
  { to: '/reports',   icon: FileDown,        label: 'Reports'    },
  { to: '/settings',  icon: Settings,        label: 'Settings'   },
];

export default function Sidebar() {
  return (
    <aside className="w-48 bg-sidebar-bg flex flex-col shrink-0">
      <nav className="flex-1 py-3">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-2.5 text-sm transition-colors ${
                isActive
                  ? 'bg-sidebar-active text-white'
                  : 'text-sidebar-text hover:bg-sidebar-hover hover:text-white'
              }`
            }
          >
            <item.icon size={16} />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div className="px-4 py-3 text-[10px] text-sidebar-text/60 border-t border-white/10">
        v1.0.0
      </div>
    </aside>
  );
}
