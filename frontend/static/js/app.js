// SOC Admin Command Center - Frontend Logic with i18n (PT-BR / EN)

let ws = null;
let activeTab = 'operations';
let currentLang = localStorage.getItem('soc_lang') || 'pt';

const I18N = {
    pt: {
        subtitle: "Motor de Regras Determinístico + Núcleo de Investigação Autônomo com IA",
        orchestratorLive: "ORQUESTRADOR ONLINE",
        reconnecting: "RECONECTANDO...",
        aiEngine: "MOTOR DE IA",
        settings: "⚙️ Configurações",
        metricTotal: "Total de Alertas Ingeridos",
        metricTotalSub: "Fluxo SIEM & Syslog",
        metricLow: "Baixo Risco Auto-Triado (90%)",
        metricLowSub: "Auto-fechado / 0 Fadiga de Alertas",
        metricHigh: "Alto Risco Investigado por IA (10%)",
        metricHighSub: "Análise Profunda Multi-Agente",
        metricMttr: "Tempo Médio de Resposta (MTTR)",
        metricMttrSub: "vs 35 min da média humana",
        metricBlocks: "Bloqueios Ativos de Firewall",
        metricBlocksSub: "Automatizado / Aprovado por Analista",
        metricSavings: "Economia de Custos Estimada",
        metricSavingsSub: "Horas de analista automatizadas",
        simTitle: "⚡ Simulador de Ataques 1-Clique (Modo Demo)",
        simSub: "Dispare telemetria real do MITRE ATT&CK para testar e demonstrar o fluxo agêntico ao vivo.",
        btnSsh: "🔥 T1110 Força Bruta SSH",
        btnSudo: "👤 T1136 Usuário Sudo Indevido",
        btnSqli: "🌐 T1190 Exploit Web SQLi",
        btnRansom: "⚠️ T1486 Ransomware FIM",
        btnScan: "🔍 T1046 Varredura de Portas (Baixo)",
        tabOps: "🚨 Operações do SOC ao Vivo",
        tabMitre: "📊 Matriz MITRE ATT&CK",
        tabContainment: "🛡️ Contenção Ativa & Firewall",
        telemetryStream: "📡 Fluxo de Telemetria & Alertas ao Vivo",
        refresh: "↻ Atualizar",
        aiReasoningStream: "🧠 Orquestrador & Raciocínio da IA em Tempo Real",
        realtimeTelemetry: "Telemetria em Tempo Real",
        aiInitMessage: "[SISTEMA] Orquestrador de Agentes Autônomos inicializado. Aguardando telemetria...",
        aiInitSub: "Clique em qualquer botão de simulação acima para ver a IA triando e investigando ao vivo.",
        selectAlertPlaceholder: "Selecione um alerta investigado ou dispare uma simulação para inspecionar o relatório gerado.",
        mitreTitle: "Mapa de Calor de Cobertura de Detecção MITRE ATT&CK®",
        mitreSub: "Mapeamento das regras de detecção ativas do SIEM e playbooks de contenção autônoma por tática adversária.",
        containmentTitle: "🛡️ Firewall Perimetral & Ações de Contenção",
        containmentSub: "Bloqueios ativos, isolamento de hosts e log de auditoria Human-in-the-Loop.",
        colIp: "IP Alvo",
        colStatus: "Status",
        colReason: "Motivo",
        colBy: "Executado Por",
        colTime: "Horário",
        colAction: "Ação",
        btnUnblock: "Desbloquear",
        revoked: "Revogado",
        btnBlockIp: "🚫 Bloquear IP (Firewall Drop)",
        vtScore: "Score VirusTotal",
        abuseScore: "Score AbuseIPDB",
        geoOrigin: "Origem Geográfica",
        torExit: "Nó de Saída Tor",
        investigationTitle: "🛡️ Relatório de Investigação de Ameaça por IA",
        modalTitle: "⚙️ Configurações do SOC & Provedores de IA",
        lblProvider: "Motor de Raciocínio LLM",
        lblGemini: "Chave de API do Gemini (Opcional)",
        lblVt: "Chave de API do VirusTotal (Opcional)",
        lblAbuse: "Chave de API do AbuseIPDB (Opcional)",
        lblAuto: "Habilitar Contenção Autônoma (Auto-bloquear IPs Críticos)",
        btnCancel: "Cancelar",
        btnSave: "Salvar Configurações",
        toastFired: "⚡ Disparando cenário de ataque:",
        toastInvComplete: "🧠 Investigação de IA Concluída:",
        toastBlocked: "✅ IP bloqueado com sucesso no Firewall e AWS SG!",
        toastSaved: "✅ Configurações salvas com sucesso!"
    },
    en: {
        subtitle: "Deterministic Rule Engine + Autonomous AI Investigation Core",
        orchestratorLive: "ORCHESTRATOR LIVE",
        reconnecting: "RECONNECTING...",
        aiEngine: "AI ENGINE",
        settings: "⚙️ Settings",
        metricTotal: "Total Ingested Alerts",
        metricTotalSub: "SIEM & Syslog stream",
        metricLow: "Low Auto-Triaged (90%)",
        metricLowSub: "Auto-closed / 0 Analyst Fatigue",
        metricHigh: "High AI Investigated (10%)",
        metricHighSub: "Deep Multi-Agent Analysis",
        metricMttr: "Mean Time to Triage (MTTR)",
        metricMttrSub: "vs 35 min human average",
        metricBlocks: "Active Firewall Blocks",
        metricBlocksSub: "Automated / Analyst approved",
        metricSavings: "Estimated Cost Savings",
        metricSavingsSub: "SOC Analyst hours automated",
        simTitle: "⚡ 1-Click Live Attack Simulator (Demo Mode)",
        simSub: "Trigger realistic MITRE ATT&CK telemetry to test and demonstrate the autonomous agent workflow in real-time.",
        btnSsh: "🔥 T1110 SSH Brute Force",
        btnSudo: "👤 T1136 Rogue Sudo User",
        btnSqli: "🌐 T1190 Web SQLi Exploit",
        btnRansom: "⚠️ T1486 Ransomware FIM",
        btnScan: "🔍 T1046 Port Scan (Low)",
        tabOps: "🚨 Live SOC Operations",
        tabMitre: "📊 MITRE ATT&CK Matrix",
        tabContainment: "🛡️ Active Containment & Firewall",
        telemetryStream: "📡 Live Telemetry & Alert Stream",
        refresh: "↻ Refresh",
        aiReasoningStream: "🧠 AI Agent Orchestrator & Reasoning Stream",
        realtimeTelemetry: "Real-time Telemetry",
        aiInitMessage: "[SYSTEM] Autonomous Agent Orchestrator initialized. Waiting for incoming telemetry...",
        aiInitSub: "Click any simulation button above to watch the agent triage and investigate in real-time.",
        selectAlertPlaceholder: "Select an investigated alert or trigger a simulation to inspect the generated report.",
        mitreTitle: "MITRE ATT&CK® Detection Coverage Heatmap",
        mitreSub: "Mapping active SIEM detection rules and autonomous containment playbooks across adversary tactics.",
        containmentTitle: "🛡️ Perimeter Firewall & Containment Actions",
        containmentSub: "Active drops, host isolation, and human-in-the-loop audit log.",
        colIp: "Target IP",
        colStatus: "Status",
        colReason: "Reason",
        colBy: "Executed By",
        colTime: "Timestamp",
        colAction: "Action",
        btnUnblock: "Unblock",
        revoked: "Revoked",
        btnBlockIp: "🚫 Block IP (Firewall Drop)",
        vtScore: "VirusTotal Score",
        abuseScore: "AbuseIPDB Score",
        geoOrigin: "Geo Origin",
        torExit: "Tor Exit Node",
        investigationTitle: "🛡️ AI Threat Investigation Report",
        modalTitle: "⚙️ SOC Settings & AI Provider",
        lblProvider: "LLM Reasoning Engine",
        lblGemini: "Gemini API Key (Optional)",
        lblVt: "VirusTotal API Key (Optional)",
        lblAbuse: "AbuseIPDB API Key (Optional)",
        lblAuto: "Enable Autonomous Containment (Auto-Block Critical IPs)",
        btnCancel: "Cancel",
        btnSave: "Save Configuration",
        toastFired: "⚡ Firing attack scenario:",
        toastInvComplete: "🧠 AI Investigation Complete:",
        toastBlocked: "✅ IP successfully blocked in Firewall & AWS SG!",
        toastSaved: "✅ Settings saved successfully!"
    }
};

function t(key) {
    return (I18N[currentLang] && I18N[currentLang][key]) || key;
}

function setLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('soc_lang', lang);
    applyTranslations();
    loadAlerts();
    loadInvestigations();
    loadContainmentBlocks();
}

function applyTranslations() {
    const dict = I18N[currentLang];
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const k = el.getAttribute('data-i18n');
        if (dict[k]) el.innerText = dict[k];
    });
    
    const langBtn = document.getElementById('btn-lang-toggle');
    if (langBtn) {
        langBtn.innerText = currentLang === 'pt' ? '🇧🇷 PT-BR' : '🇺🇸 EN';
    }
}

// On Page Load
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    applyTranslations();
    initWebSocket();
    loadMetrics();
    loadAlerts();
    loadInvestigations();
    loadMitreMatrix();
    loadContainmentBlocks();
    loadSettings();
    
    // Refresh intervals
    setInterval(loadMetrics, 10000);
});

async function checkAuth() {
    const token = localStorage.getItem('soc_token');
    const userStr = localStorage.getItem('soc_user');
    
    if (!token) {
        window.location.href = '/static/login.html';
        return;
    }
    
    if (userStr) {
        try {
            const u = JSON.parse(userStr);
            const nameEl = document.getElementById('user-profile-name');
            if (nameEl) nameEl.innerText = u.full_name || u.username || 'Admin';
        } catch (e) {}
    }
}

async function handleLogout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {}
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_user');
    window.location.href = '/static/login.html';
}

// WebSocket Initialization
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    try {
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
            const el = document.getElementById('ws-status');
            if (el) {
                el.innerHTML = `<span class="pulse-dot" style="background:#10b981;"></span> ${t('orchestratorLive')}`;
                el.className = 'pulse-badge badge-low';
            }
        };
        
        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                handleWsEvent(msg);
            } catch (e) {
                console.error("WS parse error:", e);
            }
        };
        
        ws.onclose = () => {
            const el = document.getElementById('ws-status');
            if (el) {
                el.innerHTML = `<span class="pulse-dot" style="background:#ef4444;"></span> ${t('reconnecting')}`;
                el.className = 'pulse-badge badge-high';
            }
            setTimeout(initWebSocket, 3000);
        };
    } catch (err) {
        console.error("WS error:", err);
    }
}

// Handle Real-time Events
function handleWsEvent(msg) {
    const { type, data } = msg;
    
    if (type === 'NEW_ALERT') {
        prependAlertToFeed(data);
        showToast(`🚨 Alerta: ${data.rule_description.substring(0, 45)}...`, data.rule_level >= 12 ? 'crimson' : 'cyan');
    } else if (type === 'AGENT_STEP') {
        renderAgentStep(data);
    } else if (type === 'INVESTIGATION_COMPLETED') {
        renderCompletedInvestigation(data);
        loadAlerts();
        loadContainmentBlocks();
        showToast(`${t('toastInvComplete')} ${data.alert.source_ip}`, 'emerald');
    } else if (type === 'METRICS_UPDATE') {
        updateMetricsUI(data);
    } else if (type === 'CONTAINMENT_ACTION') {
        loadContainmentBlocks();
    }
}

// Switch UI Tabs
function switchTab(tabId) {
    activeTab = tabId;
    document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active-tab'));
    
    const target = document.getElementById(`tab-${tabId}`);
    if (target) target.style.display = 'block';
    
    const btn = document.getElementById(`btn-tab-${tabId}`);
    if (btn) btn.classList.add('active-tab');
    
    if (tabId === 'mitre') loadMitreMatrix();
    if (tabId === 'containment') loadContainmentBlocks();
}

// Fetch Metrics
async function loadMetrics() {
    try {
        const res = await fetch('/api/alerts/metrics');
        const data = await res.json();
        updateMetricsUI(data);
    } catch (e) {
        console.error("Failed to load metrics", e);
    }
}

function updateMetricsUI(data) {
    document.getElementById('metric-total').innerText = data.total_alerts || 0;
    document.getElementById('metric-low').innerText = data.low_alerts || 0;
    document.getElementById('metric-high').innerText = data.high_alerts || 0;
    document.getElementById('metric-blocks').innerText = data.active_firewall_blocks || 0;
    document.getElementById('metric-savings').innerText = `$${(data.estimated_cost_savings_usd || 0).toLocaleString()}`;
    document.getElementById('metric-mttr').innerText = `${data.mttr_seconds || 3.4}s`;
}

// Load Alerts Feed
async function loadAlerts() {
    try {
        const res = await fetch('/api/alerts?limit=30');
        const alerts = await res.json();
        const container = document.getElementById('alerts-container');
        if (!container) return;
        
        container.innerHTML = alerts.map(a => generateAlertCardHTML(a)).join('');
    } catch (e) {
        console.error("Failed to load alerts", e);
    }
}

function generateAlertCardHTML(a) {
    let badgeClass = 'badge-low';
    let tierText = currentLang === 'pt' ? 'BAIXO (AUTO-FECHADO)' : 'LOW (AUTO-CLOSED)';
    if (a.rule_level >= 12) {
        badgeClass = a.status === 'CONTAINED' ? 'badge-critical' : 'badge-high';
        tierText = a.status === 'CONTAINED' 
            ? (currentLang === 'pt' ? 'ALTO (CONTIDO)' : 'HIGH (CONTAINED)')
            : (currentLang === 'pt' ? 'ALTO (INVESTIGADO POR IA)' : 'HIGH (AI INVESTIGATED)');
    } else if (a.rule_level >= 7) {
        badgeClass = 'badge-medium';
        tierText = currentLang === 'pt' ? 'MÉDIO (NOTIFICADO)' : 'MEDIUM (NOTIFIED)';
    }
    
    return `
    <div class="glass-panel" style="padding: 14px; margin-bottom: 10px; cursor: pointer; border-left: 4px solid ${getSeverityColor(a.rule_level)}" onclick="selectAlert('${a.id}', '${a.source_ip}')">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <span class="pulse-badge ${badgeClass}">${tierText}</span>
            <span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${formatTime(a.timestamp)}</span>
        </div>
        <div style="font-weight:600; font-size:0.92rem; margin-bottom:6px; color:var(--text-main);">${escapeHtml(a.rule_description)}</div>
        <div style="display:flex; gap:12px; font-size:0.78rem; font-family:var(--font-mono); color:var(--text-muted);">
            <span>Alvo: <b style="color:#e2e8f0;">${a.agent_name || 'host'}</b></span>
            <span>IP Origem: <b style="color:#38bdf8;">${a.source_ip}</b></span>
            <span>MITRE: <b style="color:#a855f7;">${a.mitre_id || 'N/A'}</b></span>
        </div>
    </div>
    `;
}

function prependAlertToFeed(a) {
    const container = document.getElementById('alerts-container');
    if (container) {
        container.insertAdjacentHTML('afterbegin', generateAlertCardHTML(a));
    }
}

// 1-Click Trigger Scenario
async function triggerAttack(scenarioKey) {
    showToast(`${t('toastFired')} ${scenarioKey}...`, 'amber');
    
    const terminal = document.getElementById('agent-reasoning-terminal');
    if (terminal) {
        terminal.innerHTML = `
        <div style="color:var(--accent-amber); font-weight:600; margin-bottom:8px;">
            [ORCHESTRATOR] 🎯 Disparando telemetria para '${scenarioKey}'...
        </div>`;
    }
    
    try {
        await fetch('/api/simulator/trigger', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ scenario: scenarioKey })
        });
    } catch (e) {
        showToast(`❌ Erro: ${e}`, 'crimson');
    }
}

// Render Agent Step
function renderAgentStep(stepData) {
    const terminal = document.getElementById('agent-reasoning-terminal');
    if (!terminal) return;
    
    const stepHtml = `
    <div style="margin-bottom: 8px; border-bottom: 1px dashed rgba(56, 189, 248, 0.2); padding-bottom: 6px;">
        <span style="color:#38bdf8; font-weight:700;">[PASSO ${stepData.step}] ${stepData.name}</span>
        <div style="color:#cbd5e1; font-size:0.8rem; margin-top:2px;">↳ ${escapeHtml(stepData.details)}</div>
    </div>
    `;
    terminal.innerHTML += stepHtml;
    terminal.scrollTop = terminal.scrollHeight;
}

// Render Completed Investigation
function renderCompletedInvestigation(invData) {
    const container = document.getElementById('investigation-details-card');
    if (!container) return;
    
    const ti = invData.threat_intel || {};
    const inv = invData.investigation || {};
    const alert = invData.alert || {};
    
    container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <h3 style="color:#f8fafc; font-size:1.05rem; display:flex; align-items:center; gap:8px;">
            ${t('investigationTitle')}
        </h3>
        <span class="pulse-badge badge-critical">${inv.risk_level || 'CRÍTICO'} (Confiança: ${inv.confidence_score || 95}%)</span>
    </div>
    
    <!-- Threat Intel Metrics -->
    <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:8px; margin-bottom:14px;">
        <div style="background:rgba(0,0,0,0.3); padding:8px; border-radius:6px; border:1px solid rgba(239,68,68,0.2);">
            <div style="font-size:0.7rem; color:var(--text-muted);">${t('vtScore')}</div>
            <div style="font-size:1.1rem; font-weight:700; color:#ef4444; font-family:var(--font-mono);">${ti.vt_score || '0/91'}</div>
        </div>
        <div style="background:rgba(0,0,0,0.3); padding:8px; border-radius:6px; border:1px solid rgba(245,158,11,0.2);">
            <div style="font-size:0.7rem; color:var(--text-muted);">${t('abuseScore')}</div>
            <div style="font-size:1.1rem; font-weight:700; color:#f59e0b; font-family:var(--font-mono);">${ti.abuseipdb_score || 0}%</div>
        </div>
        <div style="background:rgba(0,0,0,0.3); padding:8px; border-radius:6px; border:1px solid rgba(56,189,248,0.2);">
            <div style="font-size:0.7rem; color:var(--text-muted);">${t('geoOrigin')}</div>
            <div style="font-size:1.1rem; font-weight:700; color:#38bdf8; font-family:var(--font-mono);">${ti.abuseipdb_country || 'Desconhecido'}</div>
        </div>
        <div style="background:rgba(0,0,0,0.3); padding:8px; border-radius:6px; border:1px solid rgba(168,85,247,0.2);">
            <div style="font-size:0.7rem; color:var(--text-muted);">${t('torExit')}</div>
            <div style="font-size:1.1rem; font-weight:700; color:#a855f7; font-family:var(--font-mono);">${ti.is_tor_exit ? 'SIM' : 'NÃO'}</div>
        </div>
    </div>
    
    <!-- AI Structured Report -->
    <div style="background:#060911; padding:14px; border-radius:8px; font-family:var(--font-mono); font-size:0.82rem; line-height:1.6; color:#e2e8f0; margin-bottom:14px; white-space:pre-wrap; border:1px solid rgba(56,189,248,0.25);">
${escapeHtml(inv.ai_summary || 'Nenhum relatório de IA disponível')}
    </div>
    
    <!-- Actions Bar -->
    <div style="display:flex; justify-content:space-between; align-items:center;">
        <div style="font-size:0.78rem; color:var(--text-muted);">
            IP Atacante: <code style="color:#38bdf8;">${alert.source_ip || ti.source_ip}</code>
        </div>
        <div style="display:flex; gap:8px;">
            <button class="btn-cyber btn-danger" onclick="executeFirewallBlock('${alert.source_ip || ti.source_ip}')">
                ${t('btnBlockIp')}
            </button>
        </div>
    </div>
    `;
}

// Load Investigations
async function loadInvestigations() {
    try {
        const res = await fetch('/api/alerts/investigations?limit=5');
        const list = await res.json();
        if (list.length > 0) {
            const first = list[0];
            renderCompletedInvestigation({
                alert: { source_ip: first.source_ip, rule_description: first.rule_description },
                threat_intel: {
                    vt_score: first.vt_score,
                    abuseipdb_score: first.abuseipdb_score,
                    abuseipdb_country: first.abuseipdb_country,
                    abuseipdb_isp: first.abuseipdb_isp,
                    is_tor_exit: first.is_tor_exit === 1
                },
                investigation: {
                    risk_level: first.risk_level,
                    confidence_score: first.confidence_score,
                    ai_summary: first.ai_summary
                }
            });
        }
    } catch (e) {
        console.error("Failed to load investigations", e);
    }
}

// Execute Firewall Block
async function executeFirewallBlock(ip) {
    if (!ip) return;
    try {
        await fetch('/api/containment/block', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                source_ip: ip,
                reason: `Contenção manual disparada pelo analista no Console SOC para ${ip}`,
                executed_by: 'ANALYST_HUMAN'
            })
        });
        showToast(t('toastBlocked'), 'emerald');
        loadContainmentBlocks();
        loadMetrics();
    } catch (e) {
        showToast(`❌ Falha: ${e}`, 'crimson');
    }
}

// Execute Firewall Unblock
async function executeFirewallUnblock(ip) {
    try {
        await fetch('/api/containment/unblock', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ source_ip: ip, executed_by: 'ANALYST_HUMAN' })
        });
        showToast(`ℹ️ IP ${ip} desbloqueado`, 'cyan');
        loadContainmentBlocks();
        loadMetrics();
    } catch (e) {
        showToast(`❌ Falha: ${e}`, 'crimson');
    }
}

// Load Containment Blocks
async function loadContainmentBlocks() {
    try {
        const res = await fetch('/api/containment/blocks');
        const blocks = await res.json();
        const tbody = document.getElementById('containment-tbody');
        if (!tbody) return;
        
        tbody.innerHTML = blocks.map(b => `
            <tr style="border-bottom:1px solid rgba(56,189,248,0.1); font-size:0.85rem;">
                <td style="padding:10px; font-family:var(--font-mono); color:#38bdf8;">${b.source_ip}</td>
                <td style="padding:10px;"><span class="pulse-badge ${b.status === 'ACTIVE' ? 'badge-high' : 'badge-low'}">${b.status === 'ACTIVE' ? 'ATIVO' : 'REVOGADO'}</span></td>
                <td style="padding:10px; color:#cbd5e1;">${escapeHtml(b.reason || '')}</td>
                <td style="padding:10px; font-family:var(--font-mono); color:var(--text-muted);">${b.executed_by}</td>
                <td style="padding:10px; font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${formatTime(b.timestamp)}</td>
                <td style="padding:10px;">
                    ${b.status === 'ACTIVE' ? `
                        <button class="btn-cyber" style="padding:4px 8px; font-size:0.75rem;" onclick="executeFirewallUnblock('${b.source_ip}')">${t('btnUnblock')}</button>
                    ` : `<span style="color:var(--text-muted);">${t('revoked')}</span>`}
                </td>
            </tr>
        `).join('');
    } catch (e) {
        console.error("Failed to load blocks", e);
    }
}

// Load MITRE Matrix
async function loadMitreMatrix() {
    try {
        const res = await fetch('/api/alerts/mitre-matrix');
        const matrix = await res.json();
        const container = document.getElementById('mitre-container');
        if (!container) return;
        
        container.innerHTML = matrix.map(m => `
            <div class="glass-panel" style="padding:16px; border-left: 4px solid ${m.active ? '#10b981' : 'rgba(255,255,255,0.1)'};">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                    <span style="font-family:var(--font-mono); font-weight:700; color:#38bdf8;">${m.id}</span>
                    <span class="pulse-badge ${m.count > 0 ? 'badge-high' : 'badge-low'}">${m.count} Alertas</span>
                </div>
                <div style="font-weight:600; font-size:0.95rem; margin-bottom:4px;">${m.name}</div>
                <div style="font-size:0.78rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.05em;">${m.tactic}</div>
            </div>
        `).join('');
    } catch (e) {
        console.error("Failed to load MITRE matrix", e);
    }
}

// Settings
async function loadSettings() {
    try {
        const res = await fetch('/api/settings');
        const data = await res.json();
        const providerSel = document.getElementById('setting-llm-provider');
        if (providerSel) providerSel.value = data.llm_provider || 'demo';
        
        const autoCheck = document.getElementById('setting-auto-containment');
        if (autoCheck) autoCheck.checked = data.auto_containment_enabled;
        
        const badge = document.getElementById('active-llm-badge');
        if (badge) badge.innerText = (data.llm_provider || 'DEMO').toUpperCase();
    } catch (e) {
        console.error("Failed to load settings", e);
    }
}

async function saveSettings() {
    const provider = document.getElementById('setting-llm-provider').value;
    const autoCont = document.getElementById('setting-auto-containment').checked;
    const geminiKey = document.getElementById('setting-gemini-key').value;
    const vtKey = document.getElementById('setting-vt-key').value;
    const abuseKey = document.getElementById('setting-abuse-key').value;
    
    try {
        await fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                llm_provider: provider,
                auto_containment_enabled: autoCont,
                gemini_api_key: geminiKey || undefined,
                virustotal_api_key: vtKey || undefined,
                abuseipdb_api_key: abuseKey || undefined
            })
        });
        showToast(t('toastSaved'), 'emerald');
        toggleModal('settings-modal', false);
        loadSettings();
    } catch (e) {
        showToast(`❌ Falha: ${e}`, 'crimson');
    }
}

function toggleModal(modalId, show) {
    const el = document.getElementById(modalId);
    if (el) el.style.display = show ? 'flex' : 'none';
}

function toggleLanguage() {
    const newLang = currentLang === 'pt' ? 'en' : 'pt';
    setLanguage(newLang);
}

// Helpers
function getSeverityColor(level) {
    if (level >= 13) return '#ef4444';
    if (level >= 12) return '#f59e0b';
    if (level >= 7) return '#38bdf8';
    return '#10b981';
}

function formatTime(isoStr) {
    if (!isoStr) return '';
    const d = new Date(isoStr);
    return d.toLocaleTimeString();
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function showToast(text, color = 'cyan') {
    const toast = document.createElement('div');
    toast.className = 'glass-panel';
    toast.style.position = 'fixed';
    toast.style.bottom = '24px';
    toast.style.right = '24px';
    toast.style.padding = '12px 20px';
    toast.style.zIndex = '9999';
    toast.style.fontSize = '0.85rem';
    toast.style.fontWeight = '600';
    toast.style.borderLeft = `4px solid var(--accent-${color})`;
    toast.innerText = text;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}
