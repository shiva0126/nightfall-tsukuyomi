import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  Activity,
  Shield,
  Search,
  BarChart3,
  Zap,
  Target,
  Link2,
  FileText,
  ChevronLeft,
} from 'lucide-react';

interface NavItem {
  icon: any;
  label: string;
  path: string;
  badge?: number;
  category?: string;
}

interface SidebarProps {
  currentPath: string;
  onNavigate: (path: string) => void;
}

export function Sidebar({ currentPath, onNavigate }: SidebarProps) {
  const navItems: NavItem[] = [
    { icon: LayoutDashboard, label: 'Dashboard', path: 'dashboard', category: 'Overview' },
    { icon: Activity, label: 'Active Scans', path: 'active-scans', badge: 2, category: 'Scanning' },
    { icon: Shield, label: 'Passive Intel', path: 'passive-intel', category: 'Scanning' },
    { icon: Search, label: 'All Findings', path: 'findings', category: 'Analysis' },
    { icon: BarChart3, label: 'OWASP Top 10', path: 'owasp', category: 'Analysis' },
    { icon: Zap, label: 'CVE Intelligence', path: 'cve', category: 'Analysis' },
    { icon: Target, label: 'MITRE ATT&CK', path: 'mitre', category: 'Frameworks' },
    { icon: Link2, label: 'Kill Chain', path: 'killchain', category: 'Frameworks' },
    { icon: FileText, label: 'Reports', path: 'reports', category: 'Export' },
  ];

  const categories = ['Overview', 'Scanning', 'Analysis', 'Frameworks', 'Export'];

  return (
    <div className="w-60 h-screen bg-[#1a1d29] border-r border-[#2a2d3a] flex flex-col">
      {/* Logo Section */}
      <div className="h-14 px-5 border-b border-[#2a2d3a] flex items-center">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 bg-gradient-to-br from-indigo-500 to-purple-600 rounded flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-bold text-white tracking-tight">
              Nightfall
            </span>
            <span className="text-[9px] text-slate-500 font-medium tracking-wider uppercase">
              Security Platform
            </span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2">
        {categories.map((category) => (
          <div key={category} className="mb-5">
            <div className="px-3 mb-1.5 text-[10px] font-semibold text-slate-600 tracking-wider uppercase">
              {category}
            </div>
            <div className="space-y-0.5">
              {navItems
                .filter((item) => item.category === category)
                .map((item) => {
                  const Icon = item.icon;
                  const isActive = currentPath === item.path;
                  
                  return (
                    <motion.button
                      key={item.path}
                      onClick={() => onNavigate(item.path)}
                      whileHover={{ x: 2 }}
                      whileTap={{ scale: 0.98 }}
                      className={`
                        w-full flex items-center gap-2.5 px-3 py-2 rounded
                        transition-all duration-150 group relative
                        ${
                          isActive
                            ? 'bg-indigo-600 text-white'
                            : 'text-slate-400 hover:text-white hover:bg-[#252836]'
                        }
                      `}
                    >
                      {/* Active Indicator */}
                      {isActive && (
                        <motion.div
                          layoutId="activeTab"
                          className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-indigo-400 rounded-r"
                        />
                      )}

                      {/* Icon */}
                      <Icon className="w-[18px] h-[18px] flex-shrink-0" strokeWidth={2} />

                      {/* Label */}
                      <span className="text-[13px] font-medium flex-1 text-left">
                        {item.label}
                      </span>

                      {/* Badge */}
                      {item.badge && (
                        <span className="bg-red-500 text-white text-[10px] px-1.5 py-0.5 rounded font-semibold min-w-[18px] text-center">
                          {item.badge}
                        </span>
                      )}
                    </motion.button>
                  );
                })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-3 border-t border-[#2a2d3a]">
        <div className="flex items-center justify-between text-[10px] text-slate-600">
          <span>v1.0.0</span>
          <span>© 2026</span>
        </div>
      </div>
    </div>
  );
}
