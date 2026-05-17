// SOC PILOTS — main app
const { useState: useStateA, useEffect: useEffectA } = React;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "theme":   "default",
  "accent":  "#22d3ee",
  "density": "comfortable"
}/*EDITMODE-END*/;

// Map accent hex → CSS class name
const ACCENT_MAP = {
  '#22d3ee': 'cyan',
  '#a78bfa': 'violet',
  '#fbbf24': 'amber',
  '#34d399': 'green',
};

function App() {
  const [page, setPage] = useStateA('dashboard');
  const [openCase, setOpenCase] = useStateA(null);   // case detail sheet
  const [runbookCase, setRunbookCase] = useStateA(null); // runbook modal (over the sheet)
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);

  useEffectA(() => {
    const accentClass = ACCENT_MAP[t.accent] || 'cyan';
    document.documentElement.className =
      `theme-${t.theme} accent-${accentClass} density-${t.density}`;
  }, [t.theme, t.accent, t.density]);

  useEffectA(() => {
    window.socNav = setPage;
    return () => { delete window.socNav; };
  }, [setPage]);

  function renderPage() {
    switch (page) {
      // Overview
      case 'dashboard':     return <PageDashboard />;
      case 'alerts':        return <PageAlerts />;
      case 'investigation': return <PageInvestigation />;
      case 'notifications': return <PageNotifications />;
      // Detect
      case 'mitre':         return <PageMitre />;
      case 'rules':         return <PageRules />;
      case 'create-rules':  return <PageCreateRules />;
      case 'hunt':          return <PageHunt />;
      case 'log-sources':   return <PageLogSources />;
      // Investigate
      case 'copilot':       return <PageCopilot />;
      case 'langchain':     return <PageLangChain />;
      case 'correlation':   return <PageCorrelation />;
      case 'ioc':           return <PageIOC />;
      // Analytics
      case 'ueba':          return <PageUEBA />;
      case 'artifacts':     return <PageArtifacts />;
      case 'evidence':      return <PageEvidence />;
      case 'map':           return <PageMap />;
      // Respond
      case 'cases':         return <PageCases onOpenCase={setOpenCase} />;
      case 'sp-alerts':     return <PageSPAlerts />;
      case 'darksoc':       return <PageDarkSOC />;
      case 'sla':           return <PageSLA />;
      // System
      case 'agents':        return <PageAgents />;
      case 'assets':        return <PageAssets />;
      case 'vulns':         return <PageVulns />;
      case 'reports':       return <PageReports />;
      case 'users':         return <PageUsers />;
      case 'settings':      return <PageSettings />;
      case 'profile':       return <PageProfile />;
      default:              return <PageDashboard />;
    }
  }

  return (
    <div className="app">
      <Sidebar current={page} onNav={setPage} />
      <div className="main">
        {renderPage()}
      </div>
      <TweaksPanel title="Tweaks">
        <TweakSection label="Theme" />
        <TweakRadio
          label="Tone"
          value={t.theme}
          options={[
            { value: 'default',  label: 'Default' },
            { value: 'midnight', label: 'Midnight' },
            { value: 'contrast', label: 'High' },
          ]}
          onChange={v => setTweak('theme', v)}
        />
        <TweakColor
          label="Accent"
          value={t.accent}
          options={['#22d3ee', '#a78bfa', '#fbbf24', '#34d399']}
          onChange={v => setTweak('accent', v)}
        />
        <TweakSection label="Layout" />
        <TweakRadio
          label="Density"
          value={t.density}
          options={[
            { value: 'comfortable', label: 'Roomy' },
            { value: 'compact',     label: 'Compact' },
          ]}
          onChange={v => setTweak('density', v)}
        />
        <TweakSection label="Navigation" />
        <TweakSelect
          label="Jump to"
          value={page}
          options={[
            { value: 'dashboard',     label: 'Dashboard' },
            { value: 'alerts',        label: 'Alerts' },
            { value: 'investigation', label: 'Investigations' },
            { value: 'notifications', label: 'Notifications' },
            { value: 'mitre',         label: 'ATT&CK Coverage' },
            { value: 'rules',         label: 'Detection Rules' },
            { value: 'create-rules',  label: 'Create Rules' },
            { value: 'hunt',          label: 'Threat Hunt' },
            { value: 'log-sources',   label: 'Log Sources' },
            { value: 'copilot',       label: 'SOCPilots AI' },
            { value: 'langchain',     label: 'LangChain Health' },
            { value: 'correlation',   label: 'Correlation' },
            { value: 'ioc',           label: 'IOC Enrichment' },
            { value: 'ueba',          label: 'UEBA' },
            { value: 'artifacts',     label: 'IOC Store' },
            { value: 'evidence',      label: 'Evidence' },
            { value: 'map',           label: 'Live Threat Map' },
            { value: 'cases',         label: 'SP-CM Cases' },
            { value: 'sp-alerts',     label: 'SP-CM Alerts' },
            { value: 'darksoc',       label: 'Dark SOC' },
            { value: 'sla',           label: 'SLA Management' },
            { value: 'agents',        label: 'Agents' },
            { value: 'assets',        label: 'Assets' },
            { value: 'vulns',         label: 'Vulnerabilities' },
            { value: 'reports',       label: 'Reports' },
            { value: 'users',         label: 'Users' },
            { value: 'settings',      label: 'Settings' },
          ]}
          onChange={setPage}
        />
      </TweaksPanel>
      <CommandPalette onNav={setPage} page={page} />
      <CaseDetailSheet openCase={openCase} onClose={() => setOpenCase(null)} onOpenRunbook={(c) => setRunbookCase(c)} />
      <RunbookModal openCase={runbookCase} onClose={() => setRunbookCase(null)} />
      <ToastHost />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
