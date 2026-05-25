import React, { useState, useEffect, useContext } from 'react';
import api from '../utils/api';
import { AuthContext } from '../context/AuthContext';
import { socket } from '../utils/socket';
import toast from 'react-hot-toast';
import { ShieldAlert, Activity, Users, Shield, Globe2, AlertTriangle, Monitor, CheckCircle, XCircle, TrendingUp, Lock } from 'lucide-react';
import { motion } from 'framer-motion';
import { Line } from 'react-chartjs-2';
import AttackerMap from '../components/AttackerMap';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler);

const StatCard = ({ title, value, icon, color, sub, delay }) => {
  const Icon = icon;
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className={`cyber-card p-6 border-l-4 ${color} relative overflow-hidden group`}
    >
      <div className={`absolute -right-4 -top-4 w-24 h-24 opacity-5 rounded-full group-hover:scale-150 transition-transform duration-500 ${color.replace('border-', 'bg-')}`}></div>
      <div className="flex justify-between items-start mb-4">
        <div>
          <p className="text-gray-400 font-mono text-xs uppercase tracking-wider mb-1">{title}</p>
          <h3 className="text-3xl font-bold text-white">{value ?? '—'}</h3>
        </div>
        <div className={`p-3 rounded-lg bg-cyber-900 border ${color}`}>
          <Icon className={`${color.replace('border-', 'text-')} w-6 h-6`} />
        </div>
      </div>
      {sub && <p className="text-xs text-gray-500 font-mono mt-1">{sub}</p>}
    </motion.div>
  );
};

const Dashboard = () => {
  const { user } = useContext(AuthContext);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState(null);
  const [loginHistory, setLoginHistory] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [mapAttacks, setMapAttacks] = useState([]);

  const fetchAll = async () => {
    try {
      const [scoreRes, historyRes, timelineRes, mapRes] = await Promise.allSettled([
        api.get('/security/security-score'),
        api.get('/security/login-history'),
        api.get('/security/attack-timeline'),
        api.get('/security/attack-map'),
      ]);

      if (scoreRes.status === 'fulfilled') {
        setStats(scoreRes.value.data);
      }
      if (historyRes.status === 'fulfilled') {
        const raw = historyRes.value.data;
        setLoginHistory(Array.isArray(raw) ? raw.slice(0, 10) : []);
      }
      if (timelineRes.status === 'fulfilled') {
        setTimeline(timelineRes.value.data || []);
      }
      if (mapRes.status === 'fulfilled') {
        setMapAttacks(mapRes.value.data || []);
      }
    } catch (err) {
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
  }, []);

  // ================= REAL-TIME SOCKET LISTENER =================
  useEffect(() => {
    if (user?.id) {
      socket.emit('join_user_room', user.id);
    }

    socket.on('new_attack', (data) => {
      toast.error(`[AI Alert] ${data.attackType} from ${data.ip} on ${data.website}`, {
        icon: '🛡️',
        duration: 5000
      });

      setLoginHistory((prev) => {
        if (prev.some(p => p.ip === data.ip && p.createdAt === data.time)) return prev;
        return [
          {
            ip: data.ip,
            attackType: data.attackType,
            severity: data.severity,
            status: 'failed',
            country: data.location?.country || '—',
            createdAt: data.time
          },
          ...prev
        ].slice(0, 30);
      });

      // Update Map Live
      if (data.location?.latitude && data.location?.longitude) {
        setMapAttacks(prev => [
          {
            _id: Date.now().toString(), // Temporary ID for React key
            ip: data.ip,
            latitude: data.location.latitude,
            longitude: data.location.longitude,
            attackType: data.attackType,
            severity: data.severity,
            city: data.location.city,
            state: data.location.state,
            country: data.location.country,
            createdAt: data.time
          },
          ...prev
        ].slice(0, 100));
      }

      setStats((prev) => prev ? {
        ...prev,
        totalAttacks: (prev.totalAttacks || 0) + 1,
        securityScore: Math.max(0, (prev.securityScore || 100) - 1)
      } : prev);
    });

    socket.on('dashboard_refresh', () => {
      console.log('🔄 Syncing dashboard data...');
      fetchAll();
    });

    return () => {
      socket.off('new_attack');
      socket.off('dashboard_refresh');
    };
  }, []);

  const chartData = {
    labels: timeline.map(t => t.time),
    datasets: [
      {
        label: 'Blocked / Failed Attacks',
        data: timeline.map(t => t.count),
        borderColor: '#FF003C',
        backgroundColor: 'rgba(255, 0, 60, 0.08)',
        fill: true,
        tension: 0.4,
        pointBackgroundColor: '#FF003C',
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: '#e5e7eb', font: { family: 'Fira Code', size: 11 } } },
      tooltip: {
        backgroundColor: 'rgba(13, 21, 36, 0.95)',
        titleColor: '#00F0FF',
        bodyColor: '#e5e7eb',
        borderColor: '#1B2943',
        borderWidth: 1,
      }
    },
    scales: {
      y: { grid: { color: '#1B2943' }, ticks: { color: '#9ca3af', font: { family: 'Fira Code' } } },
      x: { grid: { color: '#1B2943' }, ticks: { color: '#9ca3af', font: { family: 'Fira Code' } } }
    }
  };

  if (loading) return (
    <div className="flex h-full items-center justify-center flex-col gap-4">
      <Shield className="text-cyber-primary w-12 h-12 animate-pulse" />
      <p className="text-cyber-primary font-mono text-sm animate-pulse">LOADING_THREAT_DATA...</p>
    </div>
  );

  return (
    <div className="space-y-8 pb-10">
      {/* Header */}
      <div className="flex justify-between items-center bg-cyber-800/50 p-6 rounded-lg border border-cyber-600 backdrop-blur-sm flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold font-mono tracking-wider text-white">
            COMMAND<span className="text-cyber-primary">_CENTER</span>
          </h1>
          <p className="text-gray-400 mt-1 font-mono text-sm">
            Monitoring login threats on your protected websites
          </p>
        </div>
        <div className="flex items-center space-x-3 bg-cyber-900 border border-cyber-primary p-3 rounded-md shadow-[0_0_15px_rgba(0,240,255,0.2)]">
          <ShieldAlert className="text-cyber-primary animate-pulse w-6 h-6" />
          <div className="flex flex-col">
            <span className="text-xs text-gray-400 font-mono uppercase tracking-widest">Logged in as</span>
            <span className="text-white text-sm font-bold font-mono">{user?.name || user?.email || 'Owner'}</span>
          </div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        <StatCard
          delay={0.1}
          title="Security Score"
          value={stats ? `${stats.securityScore}/100` : '—'}
          icon={Shield}
          color="border-cyber-success"
          sub="Based on attack frequency"
        />
        <StatCard
          delay={0.2}
          title="Total Threats & Failed Attempts"
          value={stats?.totalAttacks ?? 0}
          icon={AlertTriangle}
          color="border-cyber-danger"
          sub="Failed logins + detected attacks on protected websites"
        />
        <StatCard
          delay={0.3}
          title="Blocked IPs"
          value={stats?.blockedIPs ?? 0}
          icon={Lock}
          color="border-cyber-warning"
          sub="From IP quarantine list"
        />
        <StatCard
          delay={0.4}
          title="Successful Logins"
          value={stats?.successfulLogins ?? 0}
          icon={CheckCircle}
          color="border-cyber-primary"
          sub="Verified on protected sites"
        />
      </div>

      {/* Attacker Map Intelligence */}
      <AttackerMap attacks={mapAttacks} />

      {/* Chart + Live Threat Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6" style={{ minHeight: 360 }}>
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="lg:col-span-2 cyber-card p-6 flex flex-col"
        >
          <div className="flex justify-between items-center mb-4 border-b border-cyber-600 pb-3">
            <h3 className="text-xl font-bold font-mono text-white flex items-center gap-2">
              <Activity className="text-cyber-danger w-5 h-5" />
              ATTACK_TIMELINE
            </h3>
            <span className="text-xs font-mono text-gray-500">Blocked/failed per hour on protected sites</span>
          </div>
          <div className="flex-1 min-h-0 h-60">
            <Line options={chartOptions} data={chartData} />
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.6 }}
          className="cyber-card p-6 flex flex-col overflow-hidden"
        >
          <div className="flex justify-between items-center mb-4 border-b border-cyber-600 pb-3">
            <h3 className="text-xl font-bold font-mono text-white flex items-center gap-2">
              <Globe2 className="text-cyber-danger w-5 h-5" />
              LIVE_THREATS
            </h3>
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute h-full w-full rounded-full bg-cyber-danger opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-cyber-danger"></span>
            </span>
          </div>
          <div className="flex-1 overflow-y-auto space-y-3 pr-1">
            {loginHistory.filter(h => h.status === 'failed' || h.status === 'blocked').slice(0, 6).map((log, i) => (
              <div key={i} className="bg-cyber-900 border border-cyber-danger/30 p-3 rounded flex items-start gap-3 hover:border-cyber-danger transition-colors">
                <AlertTriangle className="text-cyber-danger mt-0.5 flex-shrink-0 w-4 h-4 animate-pulse" />
                <div className="min-w-0">
                  <p className="text-sm font-bold text-white font-mono truncate">{log.ip}</p>
                  <p className="text-xs text-cyber-danger mt-0.5 truncate">{log.attackType || 'Attack'}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{log.country || '—'}</p>
                </div>
              </div>
            ))}
            {loginHistory.filter(h => h.status === 'failed' || h.status === 'blocked').length === 0 && (
              <div className="text-center text-cyber-success font-mono py-8 text-sm">
                <Shield className="w-8 h-8 mx-auto mb-2 glow-pulse" />
                ALL CLEAR. NO ACTIVE THREATS.
              </div>
            )}
          </div>
        </motion.div>
      </div>

      {/* Login History Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="cyber-card p-6"
      >
        <div className="flex justify-between items-center mb-5 border-b border-cyber-600 pb-3">
          <h3 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <Monitor className="text-cyber-success w-5 h-5" />
            LOGIN_ACTIVITY
          </h3>
          <span className="text-xs font-mono text-gray-500">Login events from protected websites</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-sm border-collapse">
            <thead>
              <tr className="text-gray-400 bg-cyber-900 border-y border-cyber-600 uppercase tracking-wider font-normal">
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4">Country</th>
                <th className="py-3 px-4">Attack Type</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody>
              {loginHistory.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-gray-500 font-mono">
                    No login activity yet. Add a website and integrate the protection API.
                  </td>
                </tr>
              )}
              {loginHistory.map((log, idx) => (
                <tr key={idx} className="border-b border-cyber-600/50 hover:bg-cyber-700/30 transition-colors">
                  <td className="py-3 px-4 text-gray-400 text-xs">
                    {new Date(log.createdAt).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                  </td>
                  <td className="py-3 px-4 font-bold text-white">{log.ip}</td>
                  <td className="py-3 px-4 text-gray-400">{log.country || '—'}</td>
                  <td className="py-3 px-4 text-gray-400">{log.attackType || '—'}</td>
                  <td className="py-3 px-4">
                    {log.status === 'success' ? (
                      <span className="flex items-center gap-1 text-cyber-success bg-cyber-success/10 px-2 py-1 rounded w-fit border border-cyber-success/20 text-xs">
                        <CheckCircle className="w-3 h-3" /> SUCCESS
                      </span>
                    ) : log.status === 'blocked' ? (
                      <span className="flex items-center gap-1 text-cyber-warning bg-cyber-warning/10 px-2 py-1 rounded w-fit border border-cyber-warning/20 text-xs">
                        <Lock className="w-3 h-3" /> BLOCKED
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-cyber-danger bg-cyber-danger/10 px-2 py-1 rounded w-fit border border-cyber-danger/20 text-xs">
                        <XCircle className="w-3 h-3" /> FAILED
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>
    </div>
  );
};

export default Dashboard;
