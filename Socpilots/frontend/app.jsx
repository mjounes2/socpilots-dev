// SOC PILOTS — main app
const { useState: useStateA, useEffect: useEffectA } = React;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "theme":   "default",
  "accent":  "#22d3ee",
  "density": "comfortable"
}/*EDITMODE-END*/;

const ACCENT_MAP = {
  '#22d3ee': 'cyan',
  '#a78bfa': 'violet',
  '#fbbf24': 'amber',
  '#34d399': 'green',
};

function App() {
  const [page, setPage] = useStateA('dashboard');
  const [openCase, setOpenCase] = useStateA(null);
  const [runbookCase, setRunbookCase] = useStateA(null);
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [ready, setReady] = useStateA(false);

  // Auth guard — redirect to login if no token
  useEffectA(() => {
    const tok = sessionStorage.getItem('soc_token');
    if (!tok) { location.href = '/login'; return; }
    // Validate token with a lightweight API call
    window.SOC_API.get('/api/me').then(r => {
      if (!r) { location.href = '/login'; }
      else { setReady(true); }
    });
  }, []);

  useEffectA(() => {
    const accentClass = ACCENT_MAP[t.accent] || 'cyan';
    document.documentElement.className =
      `theme-${t.theme} accent-${accentClass} density-${t.density}`;
  }, [t.theme, t.accent, t.density]);

  if (!ready) return (
    <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'100vh',background:'var(--bg-0)',color:'var(--fg-2)',fontFamily:'var(--mono)',fontSize:13,letterSpacing:1}}>
      LOADING SOC PILOTS…
    </div>
  );

  function renderPage() {
    switch (page) {
      case 'dashboard':   return <PageDashboard />;
      case 'alerts':      return <PageAlerts />;
      case 'copilot':     return <PageCopilot />;
      case 'cases':       return <PageCases onOpenCase={setOpenCase} />;
      case 'correlation': return <PageCorrelation />;
      case 'hunt':        return <PageHunt />;
      case 'ioc':         return <PageIOC />;
      case 'agents':      return <PageAgents />;
      case 'rules':       return <PageRules />;
      case 'vulns':       return <PageVulns />;
      case 'reports':     return <PageReports />;
      case 'map':         return <PageMap />;
      case 'sp-alerts':   return <PageSPAlerts />;
      case 'settings':    return <PageSettings />;
      default:            return <PageDashboard />;
    }
  }

  return (
    <div className="app">
      <Sidebar current={page} onNav={setPage} onLogout={() => window.SOC_API.logout()} />
      <div className="main">
        {renderPage()}
      </div>
      <TweaksPanel title="Tweaks">
        <TweakSection label="Theme" />
        <TweakRadio label="Tone" value={t.theme}
          options={[{value:'default',label:'Default'},{value:'midnight',label:'Midnight'},{value:'contrast',label:'High'}]}
          onChange={v => setTweak('theme', v)} />
        <TweakColor label="Accent" value={t.accent}
          options={['#22d3ee','#a78bfa','#fbbf24','#34d399']}
          onChange={v => setTweak('accent', v)} />
        <TweakSection label="Layout" />
        <TweakRadio label="Density" value={t.density}
          options={[{value:'comfortable',label:'Roomy'},{value:'compact',label:'Compact'}]}
          onChange={v => setTweak('density', v)} />
        <TweakSection label="Navigation" />
        <TweakSelect label="Jump to" value={page}
          options={[
            {value:'dashboard',label:'Dashboard'},{value:'alerts',label:'Alerts'},
            {value:'copilot',label:'SOCPilots AI'},{value:'cases',label:'SP-CM Cases'},
            {value:'correlation',label:'Correlation'},{value:'hunt',label:'Threat Hunt'},
            {value:'ioc',label:'IOC Enrichment'},{value:'agents',label:'Agents'},
            {value:'rules',label:'Detection Rules'},{value:'vulns',label:'Vulnerabilities'},
            {value:'reports',label:'Reports'},{value:'map',label:'Live Threat Map'},
            {value:'sp-alerts',label:'SP-CM Alerts'},{value:'settings',label:'Settings'},
          ]}
          onChange={setPage} />
      </TweaksPanel>
      <CommandPalette onNav={setPage} page={page} />
      <CaseDetailSheet openCase={openCase} onClose={() => setOpenCase(null)} onOpenRunbook={c => setRunbookCase(c)} />
      <RunbookModal openCase={runbookCase} onClose={() => setRunbookCase(null)} />
      <ToastHost />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
