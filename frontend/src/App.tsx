import { useEffect, useState } from 'react';
import { Shield, Server, Activity, AlertTriangle, AlertCircle, CheckCircle2, ShieldAlert, Zap, Loader2 } from 'lucide-react';
import {
  getAlerts,
  triggerNormalAccess,
  triggerSuspiciousAccess,
  triggerUnauthorizedExport
} from './api';

interface Alert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detected_at: string;
  risk_score: number;
  summary: string;
  description: string;
}

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<string | null>(null);

  const fetchAlerts = async () => {
    try {
      const data = await getAlerts();
      setAlerts(data.alerts || data);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleDemoAction = async (action: string, apiCall: () => Promise<any>) => {
    setLoading(action);
    try {
      await apiCall();
      await fetchAlerts();
    } catch (error) {
      console.error(`Failed to execute ${action}:`, error);
    } finally {
      setLoading(null);
    }
  };

  const getSeverityColors = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-950 border-red-500/50 text-red-500';
      case 'high': return 'bg-orange-950 border-orange-500/50 text-orange-500';
      case 'medium': return 'bg-yellow-950 border-yellow-500/50 text-yellow-500';
      case 'low': return 'bg-teal-950 border-teal-500/50 text-teal-500';
      default: return 'bg-slate-900 border-slate-700 text-slate-400';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6 font-sans">
      {/* Header (System Status) */}
      <header className="mb-8 border-b border-slate-800 pb-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3 text-white">
              <Shield className="w-8 h-8 text-teal-500" />
              CareShield AI - Security Dashboard
            </h1>
            <div className="mt-2 flex items-center gap-2 text-sm text-slate-400">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
              </span>
              Live on IBM LinuxONE (s390x)
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2">
              <Activity className="w-4 h-4 text-blue-400" />
              <span className="text-sm font-medium">scikit-learn (IsolationForest)</span>
            </div>
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2">
              <Zap className="w-4 h-4 text-purple-400" />
              <span className="text-sm font-medium">IBM Granite 3.0 (LLM)</span>
            </div>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">

        {/* Sidebar (Demo Controls) */}
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2 border-b border-slate-800 pb-3">
              <Server className="w-5 h-5 text-slate-400" />
              Demo Controls
            </h2>

            <div className="space-y-3">
              <button
                onClick={() => handleDemoAction('normal', triggerNormalAccess)}
                disabled={loading !== null}
                className="w-full flex items-center justify-between px-4 py-3 bg-teal-900/30 hover:bg-teal-900/50 border border-teal-800/50 rounded-lg text-teal-400 transition-colors disabled:opacity-50"
              >
                <span className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4" />
                  Simulate Normal Access
                </span>
                {loading === 'normal' && <Loader2 className="w-4 h-4 animate-spin" />}
              </button>

              <button
                onClick={() => handleDemoAction('anomaly', triggerSuspiciousAccess)}
                disabled={loading !== null}
                className="w-full flex items-center justify-between px-4 py-3 bg-orange-900/30 hover:bg-orange-900/50 border border-orange-800/50 rounded-lg text-orange-400 transition-colors disabled:opacity-50"
              >
                <span className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Simulate Mass Access Anomaly
                </span>
                {loading === 'anomaly' && <Loader2 className="w-4 h-4 animate-spin" />}
              </button>

              <button
                onClick={() => handleDemoAction('export', triggerUnauthorizedExport)}
                disabled={loading !== null}
                className="w-full flex items-center justify-between px-4 py-3 bg-red-900/30 hover:bg-red-900/50 border border-red-800/50 rounded-lg text-red-400 transition-colors disabled:opacity-50"
              >
                <span className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4" />
                  Simulate Unauthorized Export
                </span>
                {loading === 'export' && <Loader2 className="w-4 h-4 animate-spin" />}
              </button>
            </div>
          </div>
        </div>

        {/* Main Content (Alert Feed) */}
        <div className="lg:col-span-3">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg min-h-[500px]">
            <h2 className="text-lg font-semibold mb-6 flex items-center gap-2 border-b border-slate-800 pb-3">
              <AlertCircle className="w-5 h-5 text-slate-400" />
              Security Alert Feed
            </h2>

            <div className="space-y-4">
              {alerts.length === 0 ? (
                <div className="text-center py-12 text-slate-500">
                  <Shield className="w-12 h-12 mx-auto mb-3 opacity-20" />
                  <p>System secure. No alerts detected.</p>
                </div>
              ) : (
                alerts.map((alert, index) => (
                  <div key={alert.id || index} className={`p-4 rounded-xl border ${getSeverityColors(alert.severity)} bg-opacity-10`}>
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-3 gap-2">
                      <div className="flex items-center gap-3">
                        <span className={`px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider ${getSeverityColors(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        <span className="text-sm opacity-70">
                          {new Date(alert.detected_at).toLocaleString()}
                        </span>
                      </div>
                      <div className="text-sm font-medium bg-black/20 px-3 py-1 rounded-full">
                        Risk Score: {alert.risk_score.toFixed(2)}
                      </div>
                    </div>

                    <p className="mb-4 text-slate-300 font-medium">
                      {alert.description || 'Suspicious activity detected.'}
                    </p>

                    {/* ✨ IBM Granite Reasoning Highlight */}
                    {alert.summary && (
                      <div className="mt-3 bg-purple-950/40 border border-purple-800/50 rounded-lg p-4 relative overflow-hidden">
                        <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-purple-500 to-blue-500"></div>
                        <div className="flex items-start gap-3">
                          <Zap className="w-5 h-5 text-purple-400 mt-0.5 shrink-0" />
                          <div>
                            <h4 className="text-xs font-bold text-purple-300 uppercase tracking-wider mb-1 flex items-center gap-1">
                              ✨ IBM Granite Reasoning
                            </h4>
                            <p className="text-sm text-purple-100/90 leading-relaxed">
                              {alert.summary}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;
