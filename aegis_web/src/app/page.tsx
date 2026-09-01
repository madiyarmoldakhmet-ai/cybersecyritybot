'use client';

import { useState, useEffect, useRef, FormEvent } from 'react';
import { TerminalWindow, ScanEvent } from '@/components/TerminalWindow';
import { MetricsDashboard } from '@/components/MetricsDashboard';
import { SecurityScore } from '@/components/SecurityScore';
import { Shield, Play } from 'lucide-react';
import { motion } from 'framer-motion';

export default function Home() {
  const [repoUrl, setRepoUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [scannedFiles, setScannedFiles] = useState(0);
  const [totalFiles, setTotalFiles] = useState(0);
  const [vulnerabilities, setVulnerabilities] = useState(0);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [score, setScore] = useState(100);
  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, []);

  const handleScan = (e: FormEvent) => {
    e.preventDefault();
    if (!repoUrl) return;

    // Reset state
    setEvents([]);
    setScannedFiles(0);
    setTotalFiles(0);
    setVulnerabilities(0);
    setElapsedTime(0);
    setScore(100);
    setIsScanning(true);

    if (timerRef.current) clearInterval(timerRef.current);
    timerRef.current = setInterval(() => {
      setElapsedTime(prev => prev + 1);
    }, 1000);

    const ws = new WebSocket('ws://localhost:8000/ws/scan');
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ github_url: repoUrl }));
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setEvents(prev => [...prev, data]);

      if (data.event_type === 'ScanStarted' && data.total_files) {
        setTotalFiles(data.total_files);
      } else if (data.event_type === 'FileScanning') {
        setScannedFiles(prev => prev + 1);
      } else if (data.event_type === 'VulnerabilityFound') {
        setVulnerabilities(prev => prev + 1);
        // Calculate score
        const severityStr = data.severity?.toLowerCase() || 'medium';
        let deduct = 5;
        if (severityStr === 'critical') deduct = 20;
        else if (severityStr === 'high') deduct = 10;
        else if (severityStr === 'low') deduct = 2;
        
        setScore(prev => Math.max(0, prev - deduct));
      } else if (data.event_type === 'ScanCompleted') {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      } else if (data.event_type === 'SystemError') {
        setIsScanning(false);
        if (timerRef.current) clearInterval(timerRef.current);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket Error', error);
      setIsScanning(false);
      if (timerRef.current) clearInterval(timerRef.current);
    };

    ws.onclose = () => {
      setIsScanning(false);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8 font-sans">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <header className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-white">Aegis AI Security Engine</h1>
            <p className="text-slate-400">Real-time vulnerability analysis for Flutter & AI DevSecOps</p>
          </div>
        </header>

        {/* Scan Input */}
        <form onSubmit={handleScan} className="flex gap-4">
          <input
            type="text"
            placeholder="https://github.com/owner/repo"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            disabled={isScanning}
            className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={isScanning || !repoUrl}
            className="bg-blue-600 hover:bg-blue-500 text-white font-medium px-6 py-3 rounded-xl flex items-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isScanning ? (
              <span className="flex items-center gap-2">
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Scanning...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <Play className="w-4 h-4 fill-current" />
                Launch Scan
              </span>
            )}
          </button>
        </form>

        {/* Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          
          <div className="col-span-1 lg:col-span-3 space-y-8">
            <MetricsDashboard
              scannedFiles={scannedFiles}
              totalFiles={totalFiles}
              vulnerabilities={vulnerabilities}
              elapsedTime={elapsedTime}
            />
            
            <div className="h-[500px]">
              <TerminalWindow events={events} className="h-full" />
            </div>
          </div>
          
          <div className="col-span-1">
            <SecurityScore score={score} className="h-full" />
          </div>

        </div>
      </div>
    </div>
  );
}
