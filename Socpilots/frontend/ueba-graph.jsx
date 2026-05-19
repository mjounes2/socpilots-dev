// UEBA — D3 force-directed graph that renders REAL Neo4j data.
// Exposed globally as window.UEBAForceGraph. Consumed by PageUEBA.
// Props:
//   data       — { nodes: [{id,type,risk,events,anomalies,last_seen,last_anomaly}],
//                  edges: [{source,target,rel,deviation,flags,time}] }
//   height     — pixels (default 460)
//   onNodeClick(node) — called when user clicks a node
//   onExpand(id)      — called when user dbl-clicks a node (load neighborhood)
//   selectedId — externally controlled selection (optional)
//   loading    — show spinner overlay

const { useState: useUFGS, useEffect: useUFGE, useRef: useUFGR } = React;

const TYPE_STYLE = {
  User:    { color: 'oklch(0.82 0.14 200)', r: 13, glyph: 'U' },
  Host:    { color: 'oklch(0.78 0.16 50)',  r: 15, glyph: 'H' },
  Process: { color: 'oklch(0.85 0.16 90)',  r: 10, glyph: 'P' },
  IP:      { color: 'oklch(0.68 0.20 22)',  r: 11, glyph: '⬢' },
  Network: { color: 'oklch(0.68 0.20 22)',  r: 11, glyph: '⬢' },
  Unknown: { color: 'oklch(0.65 0.04 250)', r: 10, glyph: '?' },
};

function riskColor(risk) {
  if (risk >= 70) return 'oklch(0.68 0.20 22)';
  if (risk >= 40) return 'oklch(0.80 0.16 70)';
  if (risk >= 20) return 'oklch(0.80 0.14 110)';
  return 'oklch(0.78 0.10 150)';
}

function UEBAForceGraph({ data, height = 460, onNodeClick, onExpand, selectedId, loading }) {
  const ref = useUFGR(null);
  const wrapRef = useUFGR(null);
  const [width, setWidth] = useUFGS(800);
  const [internalSelected, setInternalSelected] = useUFGS(null);
  const [filterType, setFilterType] = useUFGS('all');
  const [highRiskOnly, setHighRiskOnly] = useUFGS(false);

  const selected = selectedId !== undefined ? selectedId : internalSelected;
  const select = (next) => {
    if (selectedId !== undefined) return;
    if (typeof next === 'function') setInternalSelected(next);
    else setInternalSelected(next);
  };

  // Resize observer
  useUFGE(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver(es => {
      for (const e of es) setWidth(Math.max(400, e.contentRect.width));
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  // D3 simulation
  useUFGE(() => {
    if (!ref.current || !window.d3) return;
    const d3 = window.d3;
    const svg = d3.select(ref.current);
    svg.selectAll('*').remove();

    const nodesAll = (data?.nodes || []).map(n => ({ ...n }));
    const linksAll = (data?.edges || data?.links || []).map(l => ({ ...l }));
    if (!nodesAll.length) return;

    // Filter
    let nodes = nodesAll;
    if (filterType !== 'all') nodes = nodes.filter(n => (n.type || 'Unknown') === filterType);
    if (highRiskOnly)         nodes = nodes.filter(n => (n.risk || 0) >= 40);
    const okIds = new Set(nodes.map(n => n.id));
    let links = linksAll.filter(l => {
      const s = typeof l.source === 'object' ? l.source.id : l.source;
      const t = typeof l.target === 'object' ? l.target.id : l.target;
      return okIds.has(s) && okIds.has(t);
    });

    const w = width, h = height;
    svg.attr('viewBox', `0 0 ${w} ${h}`);

    // Glow filter
    const defs = svg.append('defs');
    const glow = defs.append('filter').attr('id', 'uf-glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    glow.append('feGaussianBlur').attr('stdDeviation', 2.5);
    const merge = glow.append('feMerge');
    merge.append('feMergeNode'); merge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Force sim
    const sim = d3.forceSimulation(nodes)
      .force('link',     d3.forceLink(links).id(d => d.id).distance(d => 65 + (d.deviation || 0) * 0.3).strength(0.5))
      .force('charge',   d3.forceManyBody().strength(-240))
      .force('center',   d3.forceCenter(w / 2, h / 2))
      .force('collision', d3.forceCollide().radius(d => (TYPE_STYLE[d.type]?.r || 10) + 7));

    // Edges — curved paths
    const linkSel = svg.append('g').attr('class', 'uf-links')
      .selectAll('path')
      .data(links).enter().append('path')
      .attr('fill', 'none')
      .attr('stroke', d => {
        const s = typeof d.source === 'object' ? d.source.id : d.source;
        const t = typeof d.target === 'object' ? d.target.id : d.target;
        if (selected && (s === selected || t === selected)) return 'oklch(0.82 0.14 200)';
        if ((d.deviation || 0) >= 60) return 'oklch(0.68 0.20 22)';
        return 'oklch(0.34 0.014 250)';
      })
      .attr('stroke-width', d => {
        const s = typeof d.source === 'object' ? d.source.id : d.source;
        const t = typeof d.target === 'object' ? d.target.id : d.target;
        if (selected && (s === selected || t === selected)) return 1.8;
        return Math.max(0.7, Math.min(2.2, (d.deviation || 0) / 40));
      })
      .attr('opacity', d => {
        const s = typeof d.source === 'object' ? d.source.id : d.source;
        const t = typeof d.target === 'object' ? d.target.id : d.target;
        if (selected && s !== selected && t !== selected) return 0.16;
        return 0.55;
      });

    // Edge labels (only for selected node)
    const labelSel = svg.append('g').attr('class', 'uf-edge-labels')
      .selectAll('text')
      .data(links.filter(l => {
        const s = typeof l.source === 'object' ? l.source.id : l.source;
        const t = typeof l.target === 'object' ? l.target.id : l.target;
        return selected && (s === selected || t === selected);
      }))
      .enter().append('text')
      .attr('font-family', 'ui-monospace, Menlo, monospace')
      .attr('font-size', 9)
      .attr('fill', 'oklch(0.65 0.10 200)')
      .attr('text-anchor', 'middle')
      .text(d => d.rel || d.type || '');

    // Nodes
    const nodeG = svg.append('g').attr('class', 'uf-nodes')
      .selectAll('g').data(nodes).enter().append('g')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        select(prev => prev === d.id ? null : d.id);
        if (onNodeClick) onNodeClick(d);
      })
      .on('dblclick', (event, d) => {
        event.stopPropagation();
        if (onExpand) onExpand(d.id);
      })
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    // Pulse ring on selected
    nodeG.filter(d => d.id === selected)
      .append('circle')
      .attr('r', d => (TYPE_STYLE[d.type]?.r || 10) + 9)
      .attr('fill', 'none')
      .attr('stroke', 'oklch(0.82 0.14 200)')
      .attr('stroke-width', 1.5)
      .attr('opacity', 0.55);

    // Outer risk halo
    nodeG.append('circle')
      .attr('r', d => (TYPE_STYLE[d.type]?.r || 10) + 5)
      .attr('fill', d => riskColor(d.risk || 0))
      .attr('opacity', 0.15);

    // Main node circle
    nodeG.append('circle')
      .attr('r', d => TYPE_STYLE[d.type]?.r || 10)
      .attr('fill', 'oklch(0.16 0.014 250)')
      .attr('stroke', d => TYPE_STYLE[d.type]?.color || 'var(--acc)')
      .attr('stroke-width', d => d.id === selected ? 2.4 : 1.5)
      .attr('filter', 'url(#uf-glow)');

    // Type glyph (letter)
    nodeG.append('text')
      .attr('font-family', 'ui-monospace, Menlo, monospace')
      .attr('font-size', 9)
      .attr('font-weight', 600)
      .attr('text-anchor', 'middle')
      .attr('dy', 3)
      .attr('fill', d => TYPE_STYLE[d.type]?.color || 'var(--acc)')
      .attr('pointer-events', 'none')
      .text(d => TYPE_STYLE[d.type]?.glyph || '?');

    // Outer label
    nodeG.append('text')
      .attr('font-family', 'ui-monospace, Menlo, monospace')
      .attr('font-size', 10)
      .attr('dy', d => -((TYPE_STYLE[d.type]?.r || 10) + 8))
      .attr('text-anchor', 'middle')
      .attr('fill', d => d.id === selected ? 'oklch(0.82 0.14 200)' : 'oklch(0.82 0.010 250)')
      .attr('opacity', d => d.id === selected || (d.risk || 0) >= 70 ? 1 : 0)
      .style('pointer-events', 'none')
      .text(d => d.id);

    // Risk score under
    nodeG.append('text')
      .attr('font-family', 'ui-monospace, Menlo, monospace')
      .attr('font-size', 8.5)
      .attr('dy', d => (TYPE_STYLE[d.type]?.r || 10) + 12)
      .attr('text-anchor', 'middle')
      .attr('fill', d => riskColor(d.risk || 0))
      .attr('opacity', d => d.id === selected || (d.risk || 0) >= 70 ? 1 : 0)
      .style('pointer-events', 'none')
      .text(d => `risk ${d.risk || 0}`);

    // Hover reveal
    nodeG
      .on('mouseenter', function () { d3.select(this).selectAll('text').attr('opacity', 1); })
      .on('mouseleave', function (event, d) {
        d3.select(this).selectAll('text').attr('opacity', d.id === selected || (d.risk || 0) >= 70 ? 1 : 0);
        // Keep glyph always visible
        d3.select(this).select('text:nth-of-type(1)').attr('opacity', 1);
      });

    sim.on('tick', () => {
      linkSel.attr('d', d => {
        const dx = d.target.x - d.source.x, dy = d.target.y - d.source.y;
        const dr = Math.sqrt(dx * dx + dy * dy) * 1.4;
        return `M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`;
      });
      labelSel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 4);
      nodeG.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Background click deselects
    svg.on('click', () => select(null));

    return () => sim.stop();
  }, [data, width, height, selected, filterType, highRiskOnly]);

  const types = ['all', 'User', 'Host', 'Process', 'IP'];
  const empty = !data || !(data.nodes || []).length;

  return (
    <div ref={wrapRef} style={{ width: '100%', position: 'relative' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
        <div className="seg">
          {types.map(t => (
            <button key={t} className={`seg-btn ${filterType === t ? 'on' : ''}`}
                    onClick={() => setFilterType(t)} style={{ fontSize: 10.5 }}>
              {t === 'all' ? 'all' : t.toLowerCase()}
              <span className="seg-count mono">
                {t === 'all'
                  ? (data?.nodes || []).length
                  : (data?.nodes || []).filter(n => (n.type || 'Unknown') === t).length}
              </span>
            </button>
          ))}
        </div>
        <label className="mono" style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10.5, color: 'var(--fg-2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={highRiskOnly} onChange={e => setHighRiskOnly(e.target.checked)}/>
          high-risk only (≥40)
        </label>
        <div style={{ display: 'flex', gap: 10, fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--fg-3)', marginLeft: 'auto' }}>
          {Object.entries(TYPE_STYLE).filter(([k]) => k !== 'Unknown' && k !== 'Network').map(([k, v]) => (
            <span key={k} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: v.color }}/>
              {k.toLowerCase()}
            </span>
          ))}
        </div>
      </div>
      <div style={{ position: 'relative' }}>
        <svg ref={ref} width={width} height={height}
             style={{ background: 'oklch(0.155 0.012 250)', borderRadius: 4, border: '1px solid var(--ln)', display: 'block' }}/>
        {loading && (
          <div style={{
            position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'rgba(11,18,32,.55)', borderRadius: 4,
            color: 'var(--fg-2)', fontFamily: 'var(--mono)', fontSize: 12,
          }}>
            <Spinner size={20}/>&nbsp;Loading graph…
          </div>
        )}
        {empty && !loading && (
          <div style={{
            position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--fg-3)', fontFamily: 'var(--mono)', fontSize: 12,
          }}>
            No entities in graph yet
          </div>
        )}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 8, fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)' }}>
        <span>{(data?.nodes || []).length} nodes · {(data?.edges || data?.links || []).length} edges · Neo4j live</span>
        <span>click = select · dbl-click = expand · drag = reposition</span>
      </div>
    </div>
  );
}

Object.assign(window, { UEBAForceGraph });
