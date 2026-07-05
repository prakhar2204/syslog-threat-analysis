import type { DashboardStats } from '../../types';
import { SEVERITY_COLORS } from '../../utils/formatters';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis,
  LineChart, Line, CartesianGrid,
} from 'recharts';

interface Props {
  stats: DashboardStats | null;
}

const CHART_HEIGHT = 220;
const COLORS = ['#dc3545', '#e67700', '#ffc107', '#0d6efd', '#198754'];

export default function DashboardCharts({ stats }: Props) {
  if (!stats) return null;

  return (
    <div className="grid grid-cols-2 gap-3">
      {/* Threat Distribution Pie */}
      <div className="bg-bg-card border border-border rounded p-3">
        <div className="text-xs font-medium text-text-secondary mb-2">Threat Distribution</div>
        <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
          <PieChart>
            <Pie
              data={stats.rule_frequency.filter(r => r.count > 0)}
              dataKey="count"
              nameKey="rule_name"
              cx="50%" cy="50%"
              outerRadius={75}
              innerRadius={40}
              paddingAngle={2}
            >
              {stats.rule_frequency.map((_, i) => (
                <Cell key={i} fill={COLORS[i % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ fontSize: 11, border: '1px solid #dee2e6' }} />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Logs Over Time Line */}
      <div className="bg-bg-card border border-border rounded p-3">
        <div className="text-xs font-medium text-text-secondary mb-2">Log Volume Over Time</div>
        <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
          <LineChart data={stats.logs_over_time}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e9ecef" />
            <XAxis dataKey="time" tick={{ fontSize: 10 }} />
            <YAxis tick={{ fontSize: 10 }} />
            <Tooltip contentStyle={{ fontSize: 11, border: '1px solid #dee2e6' }} />
            <Line type="monotone" dataKey="count" stroke="#1a73e8" strokeWidth={1.5} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Severity Distribution Bar */}
      <div className="bg-bg-card border border-border rounded p-3">
        <div className="text-xs font-medium text-text-secondary mb-2">Severity Distribution</div>
        <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
          <BarChart data={stats.severity_distribution}>
            <XAxis dataKey="severity" tick={{ fontSize: 10 }} />
            <YAxis tick={{ fontSize: 10 }} />
            <Tooltip contentStyle={{ fontSize: 11, border: '1px solid #dee2e6' }} />
            <Bar dataKey="count" radius={[2, 2, 0, 0]}>
              {stats.severity_distribution.map((entry) => (
                <Cell
                  key={entry.severity}
                  fill={SEVERITY_COLORS[entry.severity as keyof typeof SEVERITY_COLORS] || '#adb5bd'}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Top Source IPs Horizontal Bar */}
      <div className="bg-bg-card border border-border rounded p-3">
        <div className="text-xs font-medium text-text-secondary mb-2">Top Source IPs</div>
        <ResponsiveContainer width="100%" height={CHART_HEIGHT}>
          <BarChart data={stats.top_source_ips.slice(0, 8)} layout="vertical">
            <XAxis type="number" tick={{ fontSize: 10 }} />
            <YAxis type="category" dataKey="ip" tick={{ fontSize: 10 }} width={110} />
            <Tooltip contentStyle={{ fontSize: 11, border: '1px solid #dee2e6' }} />
            <Bar dataKey="count" fill="#1a73e8" radius={[0, 2, 2, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
