#!/usr/bin/env python3
"""Generate SOCPilots UI mockup screenshots."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, Rectangle
import matplotlib.gridspec as gridspec
import numpy as np
import random

random.seed(42)
np.random.seed(42)

# ── Palette
BG    = "#0a1628"; BG2   = "#0f1e35"; B1    = "#1a2f4a"; B2    = "#244060"
CYAN  = "#00e5ff"; C2    = "#00b8d4"; GREEN = "#00e676"; RED   = "#ff1744"
ORANGE= "#ff9800"; YELL  = "#ffc107"; PURP  = "#7c4dff"; TXT   = "#e8f4fd"
TXT2  = "#8ab0d0"; TXT3  = "#4a6f8a"

SEV_COLORS = {"critical": RED, "high": ORANGE, "medium": YELL, "low": GREEN}

def set_dark_bg(fig, ax_list):
    fig.patch.set_facecolor(BG)
    for ax in ax_list:
        ax.set_facecolor(BG2)
        for spine in ax.spines.values():
            spine.set_edgecolor(B2)

def card(ax, x, y, w, h, title, value, unit="", color=CYAN, sub=""):
    bg = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.04",
                        facecolor=B1, edgecolor=color, linewidth=1.2, alpha=0.9)
    ax.add_patch(bg)
    ax.text(x+w/2, y+h-0.06, title, ha='center', va='top',
            fontsize=5, color=TXT2, fontfamily='monospace')
    ax.text(x+w/2, y+h/2-0.02, str(value), ha='center', va='center',
            fontsize=13, fontweight='bold', color=color, fontfamily='monospace')
    if unit:
        ax.text(x+w/2, y+0.07, unit, ha='center', va='bottom',
                fontsize=4.5, color=TXT3)
    if sub:
        ax.text(x+w/2, y+0.04, sub, ha='center', va='bottom',
                fontsize=4.5, color=TXT2)

def sev_badge(ax, x, y, sev, w=0.18, h=0.065):
    c = SEV_COLORS.get(sev, TXT3)
    bg = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.01",
                        facecolor=c, edgecolor=c, linewidth=0.5, alpha=0.25)
    ax.add_patch(bg)
    ax.text(x+w/2, y+h/2, sev.upper(), ha='center', va='center',
            fontsize=3.8, color=c, fontweight='bold', fontfamily='monospace')

def sidebar(ax, active="dashboard"):
    items = [
        ("dashboard","Dashboard"),("alerts","Alerts"),("investigations","Investigations"),
        ("rules","Detection Rules"),("mitre","ATT&CK Coverage"),("ueba","UEBA"),
        ("correlation","Correlation"),("darksoc","Dark SOC"),("assets","Asset Inventory"),
        ("hunt","Threat Hunting"),("notifications","Notifications"),("settings","Settings"),
    ]
    ax.set_facecolor(BG2)
    ax.set_xlim(0,1); ax.set_ylim(0,1); ax.axis('off')
    # Logo
    logo_bg = FancyBboxPatch((0.05,0.91),0.9,0.07,boxstyle="round,pad=0.01",
                             facecolor=B1, edgecolor=CYAN, linewidth=1)
    ax.add_patch(logo_bg)
    ax.text(0.5,0.945,"SOCPilots", ha='center', va='center',
            fontsize=7, fontweight='bold', color=CYAN, fontfamily='monospace')
    for i,(key,lbl) in enumerate(items):
        yp = 0.88 - i*0.072
        if key == active:
            hi = FancyBboxPatch((0.04,yp-0.025),0.92,0.052,
                                boxstyle="round,pad=0.01",
                                facecolor=CYAN, edgecolor=CYAN, linewidth=0, alpha=0.15)
            ax.add_patch(hi)
            ax.text(0.12,yp+0.004, "▶", va='center', fontsize=4, color=CYAN)
        ax.text(0.2,yp+0.004, lbl, va='center', fontsize=5,
                color=CYAN if key==active else TXT2, fontfamily='monospace')

def topbar(ax, page_title, subtitle=""):
    ax.set_facecolor(BG)
    ax.set_xlim(0,1); ax.set_ylim(0,1); ax.axis('off')
    ax.axhline(0, color=B2, lw=0.8)
    ax.text(0.01,0.55, page_title, va='center', fontsize=9,
            fontweight='bold', color=TXT, fontfamily='monospace')
    if subtitle:
        ax.text(0.01,0.15, subtitle, va='center', fontsize=5.5, color=TXT3)
    ax.text(0.98,0.55,"admin", va='center', ha='right', fontsize=5.5,
            color=TXT2, fontfamily='monospace')
    # bell
    ax.text(0.93,0.55,"[3]", va='center', ha='right', fontsize=6, color=YELL)


# ═══════════════════════════════════════════════════════════
# 1. DASHBOARD
# ═══════════════════════════════════════════════════════════
def gen_dashboard():
    fig = plt.figure(figsize=(16,10)); fig.patch.set_facecolor(BG)
    gs = gridspec.GridSpec(5, 8, figure=fig,
                           left=0.0, right=1.0, top=1.0, bottom=0.0,
                           hspace=0.4, wspace=0.3)

    ax_side = fig.add_subplot(gs[:, 0])
    ax_top  = fig.add_subplot(gs[0, 1:])
    ax_kpi  = fig.add_subplot(gs[1, 1:])
    ax_bar  = fig.add_subplot(gs[2:4, 1:5])
    ax_top5 = fig.add_subplot(gs[2:4, 5:])
    ax_foot = fig.add_subplot(gs[4, 1:])

    sidebar(ax_side, "dashboard")
    topbar(ax_top, "Security Dashboard", "Real-time SOC overview")

    # KPI cards
    ax_kpi.set_facecolor(BG); ax_kpi.set_xlim(0,7); ax_kpi.set_ylim(0,1); ax_kpi.axis('off')
    card(ax_kpi, 0.05,0.05,1.1,0.85,"TOTAL ALERTS","2,847","last 24h",CYAN)
    card(ax_kpi, 1.25,0.05,1.1,0.85,"OPEN INVESTIGATIONS","34","active",ORANGE)
    card(ax_kpi, 2.45,0.05,1.1,0.85,"CRITICAL ALERTS","12","severity",RED)
    card(ax_kpi, 3.65,0.05,1.1,0.85,"MITRE COVERAGE","68%","of 190 techniques",GREEN)
    card(ax_kpi, 4.85,0.05,1.1,0.85,"ACTIVE AGENTS","47","online",C2)
    card(ax_kpi, 6.05,0.05,0.85,0.85,"DARK SOC","ON","playbooks",PURP)

    # Alert timeline bar chart
    ax_bar.set_facecolor(BG2)
    for spine in ax_bar.spines.values(): spine.set_edgecolor(B2)
    hours = list(range(24))
    vals = [random.randint(50,350) for _ in hours]
    colors_bar = [RED if v>280 else ORANGE if v>180 else CYAN for v in vals]
    ax_bar.bar(hours, vals, color=colors_bar, alpha=0.8, width=0.7)
    ax_bar.set_facecolor(BG2); ax_bar.tick_params(colors=TXT3, labelsize=5)
    ax_bar.set_xlabel("Hour (UTC)", fontsize=6, color=TXT3)
    ax_bar.set_title("Alert Volume — Last 24h", fontsize=7, color=TXT2, pad=4)
    ax_bar.yaxis.label.set_color(TXT3)
    ax_bar.grid(axis='y', color=B2, linewidth=0.5, alpha=0.6)

    # Top 5 rules
    ax_top5.set_facecolor(BG2)
    for spine in ax_top5.spines.values(): spine.set_edgecolor(B2)
    rules = ["SSH Brute Force","Malware Detected","Priv Escalation","Lateral Movement","Data Exfil"]
    counts= [412, 287, 156, 98, 67]
    bars = ax_top5.barh(rules, counts, color=[RED,RED,ORANGE,ORANGE,YELL], alpha=0.8, height=0.6)
    ax_top5.set_facecolor(BG2); ax_top5.tick_params(colors=TXT3, labelsize=5.5)
    ax_top5.set_title("Top Triggered Rules", fontsize=7, color=TXT2, pad=4)
    ax_top5.grid(axis='x', color=B2, linewidth=0.5, alpha=0.6)
    for bar, cnt in zip(bars, counts):
        ax_top5.text(bar.get_width()+5, bar.get_y()+bar.get_height()/2,
                     str(cnt), va='center', fontsize=5.5, color=TXT2)

    # Footer: severity pie
    ax_foot.set_facecolor(BG); ax_foot.axis('off')
    ax_foot.text(0.02,0.5,"Severity Distribution:", va='center', fontsize=6, color=TXT2,
                 transform=ax_foot.transAxes)
    colors_p=[RED,ORANGE,YELL,GREEN]; labels_p=["Critical 12%","High 28%","Medium 41%","Low 19%"]
    for i,(c,l) in enumerate(zip(colors_p,labels_p)):
        patch = FancyBboxPatch((0.15+i*0.19, 0.2), 0.14, 0.6,
                               boxstyle="round,pad=0.02",
                               facecolor=c, edgecolor=c, linewidth=0, alpha=0.2,
                               transform=ax_foot.transAxes)
        ax_foot.add_patch(patch)
        ax_foot.text(0.22+i*0.19, 0.5, l, va='center', ha='center', fontsize=5.5,
                     color=c, fontweight='bold', transform=ax_foot.transAxes)

    plt.savefig("screenshot_dashboard.png", dpi=150, bbox_inches='tight',
                facecolor=BG, edgecolor='none')
    plt.close()
    print("screenshot_dashboard.png saved")


# ═══════════════════════════════════════════════════════════
# 2. MITRE COVERAGE
# ═══════════════════════════════════════════════════════════
def gen_mitre():
    fig = plt.figure(figsize=(16,10)); fig.patch.set_facecolor(BG)
    gs = gridspec.GridSpec(5, 8, figure=fig,
                           left=0.0, right=1.0, top=1.0, bottom=0.0,
                           hspace=0.3, wspace=0.2)
    ax_side = fig.add_subplot(gs[:, 0])
    ax_top  = fig.add_subplot(gs[0, 1:])
    ax_main = fig.add_subplot(gs[1:, 1:])

    sidebar(ax_side, "mitre")
    topbar(ax_top, "MITRE ATT&CK Coverage", "Enterprise Framework — 190 techniques across 14 tactics")

    ax_main.set_facecolor(BG); ax_main.axis('off')
    ax_main.set_xlim(0, 14); ax_main.set_ylim(0, 14)

    tactics = ["Recon","Resource Dev","Initial Access","Execution","Persistence",
               "Priv Esc","Def Evasion","Cred Access","Discovery","Lateral Move",
               "Collection","Exfiltration","C2","Impact"]

    # Random techniques per tactic (4-16)
    tech_counts = [4,5,8,14,16,14,15,12,16,9,10,9,16,14]
    cov_map = {}
    for col, cnt in enumerate(tech_counts):
        for row in range(cnt):
            r = random.random()
            if r < 0.35: cov_map[(col,row)] = "high"
            elif r < 0.55: cov_map[(col,row)] = "medium"
            elif r < 0.7: cov_map[(col,row)] = "low"
            else: cov_map[(col,row)] = "none"

    cov_colors = {"high":"#00c853","medium":"#ffc107","low":"#ff6d00","none":B2}
    cov_alpha  = {"high":0.85,"medium":0.75,"low":0.65,"none":0.4}

    cell_w, cell_h = 0.88, 0.48
    for col, (tac, cnt) in enumerate(zip(tactics, tech_counts)):
        xc = col * 0.98 + 0.05
        # Tactic header
        hdr = FancyBboxPatch((xc, 13.3), cell_w, 0.6,
                             boxstyle="round,pad=0.03",
                             facecolor=B1, edgecolor=CYAN, linewidth=1)
        ax_main.add_patch(hdr)
        ax_main.text(xc+cell_w/2, 13.6, tac, ha='center', va='center',
                     fontsize=4.2, fontweight='bold', color=CYAN, rotation=0,
                     fontfamily='monospace', wrap=True)

        for row in range(cnt):
            cov = cov_map.get((col,row),"none")
            yc = 13.2 - row * 0.55
            if yc < 0: break
            cc = cov_colors[cov]; ca = cov_alpha[cov]
            cell = FancyBboxPatch((xc, yc-cell_h+0.05), cell_w, cell_h,
                                  boxstyle="round,pad=0.02",
                                  facecolor=cc, edgecolor=cc, linewidth=0.3, alpha=ca)
            ax_main.add_patch(cell)
            ax_main.text(xc+cell_w/2, yc-cell_h/2+0.07,
                         f"T{1000+col*10+row:04d}", ha='center', va='center',
                         fontsize=3.2, color=TXT if cov!="none" else TXT3,
                         fontfamily='monospace')

    # Legend
    for i,(lbl,c) in enumerate([("High (≥10)",GREEN),("Medium (3-9)",YELL),
                                  ("Low (1-2)",ORANGE),("None",TXT3)]):
        lx = 0.1 + i*2.0
        p = FancyBboxPatch((lx, 0.1), 0.25, 0.3, boxstyle="round,pad=0.02",
                           facecolor=c, edgecolor=c, linewidth=0, alpha=0.7)
        ax_main.add_patch(p)
        ax_main.text(lx+0.35, 0.25, lbl, va='center', fontsize=5.5, color=TXT2)

    # Stats
    ax_main.text(13.5, 0.25, "68% Coverage  |  129/190 Techniques",
                 va='center', ha='right', fontsize=6, color=CYAN, fontweight='bold')

    plt.savefig("screenshot_mitre.png", dpi=150, bbox_inches='tight',
                facecolor=BG, edgecolor='none')
    plt.close()
    print("screenshot_mitre.png saved")


# ═══════════════════════════════════════════════════════════
# 3. AI INVESTIGATION
# ═══════════════════════════════════════════════════════════
def gen_investigation():
    fig = plt.figure(figsize=(16,10)); fig.patch.set_facecolor(BG)
    gs = gridspec.GridSpec(6, 8, figure=fig,
                           left=0.0, right=1.0, top=1.0, bottom=0.0,
                           hspace=0.3, wspace=0.3)
    ax_side  = fig.add_subplot(gs[:, 0])
    ax_top   = fig.add_subplot(gs[0, 1:])
    ax_meta  = fig.add_subplot(gs[1, 1:4])
    ax_tools = fig.add_subplot(gs[1, 4:])
    ax_rep   = fig.add_subplot(gs[2:, 1:5])
    ax_art   = fig.add_subplot(gs[2:, 5:])

    sidebar(ax_side, "investigations")
    topbar(ax_top, "Investigation Detail", "INV-2024-0847 · SSH Brute Force → Lateral Movement")

    # Meta
    ax_meta.set_facecolor(B1)
    for spine in ax_meta.spines.values(): spine.set_edgecolor(B2)
    meta = [("Status","In Progress",ORANGE),("Severity","Critical",RED),
            ("Agent","webserver-01",CYAN),("MITRE","T1110 · T1021",PURP),
            ("Created","2024-11-15 03:42",TXT2),("Rule Lvl","14",RED)]
    for i,(k,v,c) in enumerate(meta):
        xi = (i%3)*2.0+0.2; yi = 0.75 if i<3 else 0.2
        ax_meta.text(xi,yi+0.15, k, fontsize=4.5, color=TXT3, transform=ax_meta.transAxes)
        ax_meta.text(xi,yi, v, fontsize=6, fontweight='bold', color=c, transform=ax_meta.transAxes)
    ax_meta.set_title("Investigation Metadata", fontsize=6.5, color=TXT2, pad=3)

    # Tool execution trace
    ax_tools.set_facecolor(B1)
    for spine in ax_tools.spines.values(): spine.set_edgecolor(B2)
    ax_tools.axis('off'); ax_tools.set_xlim(0,1); ax_tools.set_ylim(0,1)
    ax_tools.set_title("ReAct Tool Trace", fontsize=6.5, color=TXT2, pad=3)
    steps=[("search_alerts","SSH brute-force last 2h",GREEN,0.88),
           ("enrich_ip","185.220.101.x → VT:45/72",RED,0.73),
           ("check_cases","0 related cases found",TXT3,0.58),
           ("query_ueba","user: lateral_movement score 85",ORANGE,0.43),
           ("query_shodan","Port 22,80,443 open · CVE-2023-38408",YELL,0.28),
           ("✓ Final Answer","Confirmed — APT lateral movement",CYAN,0.10)]
    for tool,desc,c,yp in steps:
        ax_tools.text(0.04,yp+0.04, f"▶ {tool}", fontsize=4.5, color=c,
                      fontweight='bold', fontfamily='monospace')
        ax_tools.text(0.08,yp, desc, fontsize=4, color=TXT3)
        ax_tools.axhline(yp-0.02, color=B2, lw=0.4, xmin=0.03, xmax=0.97)

    # Report
    ax_rep.set_facecolor(BG2)
    for spine in ax_rep.spines.values(): spine.set_edgecolor(B2)
    ax_rep.axis('off'); ax_rep.set_xlim(0,1); ax_rep.set_ylim(0,1)
    ax_rep.set_title("AI Investigation Report", fontsize=7, color=CYAN, pad=4)
    report_lines = [
        ("EXECUTIVE SUMMARY", CYAN, 7, True),
        ("A coordinated SSH brute-force attack originating from Tor exit node", TXT, 5.5, False),
        ("185.220.101.47 (VirusTotal: 45/72) targeted webserver-01 at 03:38 UTC.", TXT, 5.5, False),
        ("", TXT, 4, False),
        ("THREAT INTELLIGENCE", ORANGE, 6.5, True),
        ("• VT Score: 45/72 engines flagged as malicious", TXT2, 5.5, False),
        ("• AbuseIPDB Confidence: 98% — 847 reports in 30 days", TXT2, 5.5, False),
        ("• OTX Pulses: APT-29 Cozy Bear, Nobelium campaign", TXT2, 5.5, False),
        ("", TXT, 4, False),
        ("UEBA ANOMALIES", YELL, 6.5, True),
        ("• User john.doe: Risk Score 87/100 — Lateral Movement detected", TXT2, 5.5, False),
        ("• Impossible travel: NY → Frankfurt within 4 minutes", TXT2, 5.5, False),
        ("", TXT, 4, False),
        ("MITRE ATT&CK MAPPING", PURP, 6.5, True),
        ("T1110 Brute Force  |  T1021 Remote Services  |  T1078 Valid Accounts", TXT2, 5.5, False),
        ("", TXT, 4, False),
        ("RECOMMENDED ACTIONS", GREEN, 6.5, True),
        ("1. Block IP 185.220.101.47 at perimeter firewall immediately", TXT, 5.5, False),
        ("2. Isolate webserver-01 pending forensic investigation", TXT, 5.5, False),
        ("3. Disable account john.doe pending review", TXT, 5.5, False),
        ("4. Escalate to TheHive — case created: CS-2024-0341", CYAN, 5.5, False),
    ]
    ypos = 0.96
    for line, color, size, bold in report_lines:
        ax_rep.text(0.03, ypos, line, va='top', fontsize=size, color=color,
                    fontweight='bold' if bold else 'normal',
                    fontfamily='monospace' if bold else 'sans-serif',
                    transform=ax_rep.transAxes)
        ypos -= 0.042

    # Artifacts
    ax_art.set_facecolor(BG2)
    for spine in ax_art.spines.values(): spine.set_edgecolor(B2)
    ax_art.axis('off'); ax_art.set_xlim(0,1); ax_art.set_ylim(0,1)
    ax_art.set_title("Artifacts", fontsize=6.5, color=TXT2, pad=3)
    artifacts = [
        ("IP","185.220.101.47","Tor Exit Node",RED),
        ("IP","10.0.0.15","webserver-01",ORANGE),
        ("USER","john.doe","Compromised Account",YELL),
        ("HASH","d41d8cd9...","Suspicious Binary",PURP),
        ("DOMAIN","c2.evil.ru","C2 Server",RED),
        ("CVE","CVE-2023-38408","OpenSSH vuln",ORANGE),
    ]
    for i,(typ,val,note,c) in enumerate(artifacts):
        yp = 0.88 - i*0.14
        tp = FancyBboxPatch((0.03,yp-0.035),0.12,0.07,boxstyle="round,pad=0.01",
                            facecolor=c,edgecolor=c,linewidth=0,alpha=0.25,
                            transform=ax_art.transAxes)
        ax_art.add_patch(tp)
        ax_art.text(0.09,yp, typ, ha='center', va='center', fontsize=4,
                    color=c, fontweight='bold', transform=ax_art.transAxes)
        ax_art.text(0.18,yp, val, va='center', fontsize=5, color=TXT,
                    fontfamily='monospace', transform=ax_art.transAxes)
        ax_art.text(0.18,yp-0.052, note, va='center', fontsize=4, color=TXT3,
                    transform=ax_art.transAxes)

    plt.savefig("screenshot_investigation.png", dpi=150, bbox_inches='tight',
                facecolor=BG, edgecolor='none')
    plt.close()
    print("screenshot_investigation.png saved")


# ═══════════════════════════════════════════════════════════
# 4. UEBA GRAPH
# ═══════════════════════════════════════════════════════════
def gen_ueba():
    fig = plt.figure(figsize=(16,10)); fig.patch.set_facecolor(BG)
    gs = gridspec.GridSpec(5, 8, figure=fig,
                           left=0.0, right=1.0, top=1.0, bottom=0.0,
                           hspace=0.3, wspace=0.25)
    ax_side  = fig.add_subplot(gs[:, 0])
    ax_top   = fig.add_subplot(gs[0, 1:])
    ax_graph = fig.add_subplot(gs[1:4, 1:5])
    ax_board = fig.add_subplot(gs[1:4, 5:])
    ax_foot  = fig.add_subplot(gs[4, 1:])

    sidebar(ax_side, "ueba")
    topbar(ax_top, "UEBA — Entity Behavior Analytics", "Neo4j Graph  ·  Risk Scoring  ·  Anomaly Detection")

    # Graph
    ax_graph.set_facecolor(BG2)
    for spine in ax_graph.spines.values(): spine.set_edgecolor(B2)
    ax_graph.set_xlim(-3,3); ax_graph.set_ylim(-3,3); ax_graph.axis('off')
    ax_graph.set_title("Entity Relationship Graph", fontsize=7, color=TXT2, pad=4)

    nodes = {
        "john.doe":   (0,0,     RED,    87, "USER"),
        "webserver-01":(-1.5,1.2,ORANGE,72, "HOST"),
        "db-server":  (1.5,1.5, ORANGE,68, "HOST"),
        "admin-pc":   (-1.8,-1.2,YELL,  45, "HOST"),
        "explorer.exe":(-0.5,-2,PURP,   55, "PROC"),
        "cmd.exe":    (1.2,-1.8,PURP,   60, "PROC"),
        "10.0.0.15":  (2.5,0.2, C2,     30, "NET"),
    }
    edges = [("john.doe","webserver-01","LOGGED_IN",RED),
             ("john.doe","db-server","ACCESSED",ORANGE),
             ("john.doe","admin-pc","LOGGED_IN",YELL),
             ("webserver-01","explorer.exe","EXECUTED",PURP),
             ("explorer.exe","cmd.exe","EXECUTED",PURP),
             ("cmd.exe","10.0.0.15","CONNECTED_TO",C2),
             ("john.doe","cmd.exe","EXECUTED",RED)]

    for src,dst,rel,c in edges:
        x1,y1,_,_,_ = nodes[src]; x2,y2,_,_,_ = nodes[dst]
        ax_graph.annotate("",xy=(x2,y2),xytext=(x1,y1),
                          arrowprops=dict(arrowstyle="->",color=c,lw=1.2,alpha=0.7,
                                          connectionstyle="arc3,rad=0.15"))
        mx,my = (x1+x2)/2,(y1+y2)/2
        ax_graph.text(mx,my+0.12,rel,ha='center',fontsize=3.5,color=c,alpha=0.8)

    for name,(x,y,c,score,typ) in nodes.items():
        size = 180 + score*2
        ax_graph.scatter(x,y,s=size,c=c,alpha=0.8,zorder=5,edgecolors=c,linewidths=1.5)
        ax_graph.text(x,y,typ,ha='center',va='center',fontsize=3.5,
                      color=BG,fontweight='bold',zorder=6)
        ax_graph.text(x,y-0.28,name,ha='center',fontsize=4,color=TXT2,zorder=6)
        ax_graph.text(x,y-0.48,f"Risk: {score}",ha='center',fontsize=3.5,color=c,zorder=6)

    # Leaderboard
    ax_board.set_facecolor(BG2)
    for spine in ax_board.spines.values(): spine.set_edgecolor(B2)
    ax_board.axis('off'); ax_board.set_xlim(0,1); ax_board.set_ylim(0,1)
    ax_board.set_title("Risk Leaderboard", fontsize=7, color=TXT2, pad=4)
    leaders = [("john.doe",87,RED),("cmd.exe",72,ORANGE),("db-server",68,ORANGE),
               ("svc-backup",61,YELL),("explorer.exe",55,YELL),
               ("admin-pc",45,GREEN),("nginx-proc",38,GREEN),("10.0.0.15",30,GREEN)]
    for i,(name,score,c) in enumerate(leaders):
        yp = 0.92 - i*0.11
        bar_w = score/100 * 0.7
        bg = FancyBboxPatch((0.15,yp-0.035),0.75,0.07,boxstyle="round,pad=0.01",
                            facecolor=B1,edgecolor=B2,linewidth=0.5,
                            transform=ax_board.transAxes)
        ax_board.add_patch(bg)
        bar = FancyBboxPatch((0.15,yp-0.035),bar_w,0.07,boxstyle="round,pad=0.01",
                             facecolor=c,edgecolor=c,linewidth=0,alpha=0.4,
                             transform=ax_board.transAxes)
        ax_board.add_patch(bar)
        ax_board.text(0.05,yp,f"{i+1}",ha='center',va='center',fontsize=5,
                      color=TXT3,transform=ax_board.transAxes)
        ax_board.text(0.17,yp,name,va='center',fontsize=5,color=TXT,
                      fontfamily='monospace',transform=ax_board.transAxes)
        ax_board.text(0.92,yp,str(score),va='center',ha='right',fontsize=5.5,
                      color=c,fontweight='bold',transform=ax_board.transAxes)

    # Footer anomaly stats
    ax_foot.set_facecolor(BG); ax_foot.axis('off')
    anoms = [("Impossible Travel","2",RED),("Lateral Movement","5",ORANGE),
             ("Priv Escalation","3",ORANGE),("New Host Access","8",YELL),
             ("After-Hours","12",YELL),("High-Freq Login","7",GREEN)]
    ax_foot.text(0.01,0.6,"Anomalies Detected:",va='center',fontsize=6,
                 color=TXT2,transform=ax_foot.transAxes)
    for i,(lbl,cnt,c) in enumerate(anoms):
        xp = 0.15+i*0.14
        p = FancyBboxPatch((xp,0.1),0.12,0.8,boxstyle="round,pad=0.02",
                           facecolor=c,edgecolor=c,linewidth=0,alpha=0.18,
                           transform=ax_foot.transAxes)
        ax_foot.add_patch(p)
        ax_foot.text(xp+0.06,0.65,cnt,ha='center',va='center',fontsize=9,
                     fontweight='bold',color=c,transform=ax_foot.transAxes)
        ax_foot.text(xp+0.06,0.25,lbl,ha='center',va='center',fontsize=4,
                     color=TXT3,transform=ax_foot.transAxes)

    plt.savefig("screenshot_ueba.png", dpi=150, bbox_inches='tight',
                facecolor=BG, edgecolor='none')
    plt.close()
    print("screenshot_ueba.png saved")


# ═══════════════════════════════════════════════════════════
# 5. DARK SOC
# ═══════════════════════════════════════════════════════════
def gen_darksoc():
    fig = plt.figure(figsize=(16,10)); fig.patch.set_facecolor(BG)
    gs = gridspec.GridSpec(5, 8, figure=fig,
                           left=0.0, right=1.0, top=1.0, bottom=0.0,
                           hspace=0.35, wspace=0.25)
    ax_side  = fig.add_subplot(gs[:, 0])
    ax_top   = fig.add_subplot(gs[0, 1:])
    ax_stat  = fig.add_subplot(gs[1, 1:4])
    ax_ctrl  = fig.add_subplot(gs[1, 4:])
    ax_log   = fig.add_subplot(gs[2:, 1:])

    sidebar(ax_side, "darksoc")
    topbar(ax_top, "Dark SOC — Automated Response Engine", "Playbook execution log  ·  Consensus gates  ·  Audit trail")

    # Status cards
    ax_stat.set_facecolor(BG); ax_stat.axis('off')
    ax_stat.set_xlim(0,6); ax_stat.set_ylim(0,1)
    card(ax_stat,0.05,0.05,1.4,0.85,"ENGINE STATUS","ACTIVE","",GREEN)
    card(ax_stat,1.6,0.05,1.4,0.85,"ACTIONS TODAY","23","automated",CYAN)
    card(ax_stat,3.15,0.05,1.4,0.85,"BLOCKED IPs","15","last 24h",RED)
    card(ax_stat,4.7,0.05,1.2,0.85,"FP RATE","4.2%","30-day avg",YELL)

    # Control panel
    ax_ctrl.set_facecolor(B1)
    for spine in ax_ctrl.spines.values(): spine.set_edgecolor(B2)
    ax_ctrl.axis('off'); ax_ctrl.set_xlim(0,1); ax_ctrl.set_ylim(0,1)
    ax_ctrl.set_title("Playbook Controls", fontsize=6.5, color=TXT2, pad=3)
    controls = [("Auto Block IP","ENABLED",GREEN),("Auto Isolate Host","CONSENSUS REQ.",YELL),
                ("Kill Process","ENABLED",GREEN),("Disable User","CONSENSUS REQ.",YELL),
                ("Create Case","ENABLED",GREEN),("FP Threshold","15%",ORANGE)]
    for i,(lbl,val,c) in enumerate(controls):
        yp = 0.88 - i*0.14
        ax_ctrl.text(0.04,yp,lbl,va='center',fontsize=5,color=TXT2,transform=ax_ctrl.transAxes)
        ax_ctrl.text(0.96,yp,val,va='center',ha='right',fontsize=5,color=c,
                     fontweight='bold',fontfamily='monospace',transform=ax_ctrl.transAxes)
        ax_ctrl.axhline(yp-0.05,color=B2,lw=0.4,xmin=0.03,xmax=0.97)

    # Execution log
    ax_log.set_facecolor(BG2)
    for spine in ax_log.spines.values(): spine.set_edgecolor(B2)
    ax_log.axis('off'); ax_log.set_xlim(0,1); ax_log.set_ylim(0,1)
    ax_log.set_title("Playbook Execution Audit Log", fontsize=7, color=CYAN, pad=4)

    headers = ["Timestamp","Action","Target","Result","Agent","Playbook","FP Risk"]
    col_x   = [0.01, 0.13, 0.24, 0.38, 0.52, 0.63, 0.77]
    for h,x in zip(headers,col_x):
        ax_log.text(x,0.96,h,fontsize=5,color=TXT3,fontweight='bold',transform=ax_log.transAxes)
    ax_log.axhline(0.94,color=B2,lw=0.5,xmin=0.01,xmax=0.99)

    log_entries = [
        ("03:47:22","block_ip","185.220.101.47","✓ BLOCKED",RED,"BruteForce-Response","2%",GREEN),
        ("03:47:19","search_alerts","SSH brute force","✓ FOUND",CYAN,"BruteForce-Response","",TXT3),
        ("03:45:11","create_case","INV-2024-0847","✓ CS-0341",GREEN,"Escalation","5%",GREEN),
        ("03:42:08","isolate_host","webserver-01","[ PENDING ]",YELL,"Isolation","8%",YELL),
        ("02:31:55","kill_process","explorer.exe:4421","✓ KILLED",RED,"MalwareKill","3%",GREEN),
        ("02:30:43","block_ip","10.42.0.199","✓ BLOCKED",RED,"BruteForce-Response","1%",GREEN),
        ("01:19:22","disable_user","guest.svc","✓ DISABLED",ORANGE,"CompromisedUser","12%",YELL),
        ("00:58:11","create_case","INV-2024-0831","✓ CS-0340",GREEN,"Escalation","4%",GREEN),
        ("00:34:07","block_ip","192.0.2.88","✗ FAILED",TXT3,"BruteForce-Response","",TXT3),
        ("Yesterday","isolate_host","finance-pc","✓ ISOLATED",RED,"APTResponse","6%",GREEN),
    ]
    for i,row in enumerate(log_entries):
        ts,action,target,result,rc,pb,fp_risk,fc = row
        yp = 0.90 - i*0.088
        if i%2==0:
            rbg = FancyBboxPatch((0.005,yp-0.03),0.99,0.075,
                                 boxstyle="square,pad=0",facecolor=B1,edgecolor='none',alpha=0.4,
                                 transform=ax_log.transAxes)
            ax_log.add_patch(rbg)
        vals = [ts,action,target,result,pb,fp_risk]
        colors_r = [TXT3,CYAN,TXT,rc,TXT2,fc]
        for v,x,c in zip(vals,col_x,colors_r):
            ax_log.text(x,yp,v,va='center',fontsize=4.5,color=c,
                        fontfamily='monospace',transform=ax_log.transAxes)

    plt.savefig("screenshot_darksoc.png", dpi=150, bbox_inches='tight',
                facecolor=BG, edgecolor='none')
    plt.close()
    print("screenshot_darksoc.png saved")


# ═══════════════════════════════════════════════════════════
# 6. ALERTS PAGE
# ═══════════════════════════════════════════════════════════
def gen_alerts():
    fig = plt.figure(figsize=(16,10)); fig.patch.set_facecolor(BG)
    gs = gridspec.GridSpec(5, 8, figure=fig,
                           left=0.0, right=1.0, top=1.0, bottom=0.0,
                           hspace=0.3, wspace=0.25)
    ax_side  = fig.add_subplot(gs[:, 0])
    ax_top   = fig.add_subplot(gs[0, 1:])
    ax_filt  = fig.add_subplot(gs[1, 1:])
    ax_table = fig.add_subplot(gs[2:, 1:])

    sidebar(ax_side, "alerts")
    topbar(ax_top, "Security Alerts", "Live feed from Wazuh / OpenSearch")

    # Filters bar
    ax_filt.set_facecolor(BG); ax_filt.axis('off')
    ax_filt.set_xlim(0,1); ax_filt.set_ylim(0,1)
    filters = [("Search alerts...","",0.01,0.32),("Severity","All",0.35,0.08),
               ("Agent","All",0.45,0.08),("Timeframe","24h",0.55,0.08),
               ("MITRE","All",0.65,0.08)]
    for placeholder,val,xp,wp in filters:
        fb = FancyBboxPatch((xp,0.15),wp if wp else 0.3,0.65,boxstyle="round,pad=0.02",
                            facecolor=B1,edgecolor=B2,linewidth=0.8,transform=ax_filt.transAxes)
        ax_filt.add_patch(fb)
        ax_filt.text(xp+0.01,0.5,placeholder if not val else val,va='center',
                     fontsize=5.5,color=TXT3 if not val else TXT2,transform=ax_filt.transAxes)
    btn = FancyBboxPatch((0.75,0.15),0.09,0.65,boxstyle="round,pad=0.02",
                         facecolor=CYAN,edgecolor=CYAN,linewidth=0,alpha=0.2,
                         transform=ax_filt.transAxes)
    ax_filt.add_patch(btn)
    ax_filt.text(0.795,0.5,"Investigate AI",ha='center',va='center',fontsize=5.5,
                 color=CYAN,fontweight='bold',transform=ax_filt.transAxes)
    ax_filt.text(0.96,0.5,"2,847 alerts",ha='right',va='center',fontsize=5.5,
                 color=TXT3,transform=ax_filt.transAxes)

    # Table
    ax_table.set_facecolor(BG2)
    for spine in ax_table.spines.values(): spine.set_edgecolor(B2)
    ax_table.axis('off'); ax_table.set_xlim(0,1); ax_table.set_ylim(0,1)

    headers = ["Time","Rule ID","Severity","Description","Agent","Src IP","Lvl"]
    col_x   = [0.01,0.09,0.17,0.29,0.62,0.74,0.88]
    for h,x in zip(headers,col_x):
        ax_table.text(x,0.97,h,fontsize=5,color=TXT3,fontweight='bold',transform=ax_table.transAxes)
    ax_table.axhline(0.955,color=B2,lw=0.5)

    alert_rows = [
        ("03:47:22","100100","critical","SSH brute force — 1847 attempts","webserver-01","185.220.101.47","14"),
        ("03:45:11","100200","critical","Malware detected — Trojan.Agent","finance-pc","10.0.0.88","13"),
        ("03:42:08","100300","high","Privilege escalation via sudo","db-server","10.0.0.15","10"),
        ("03:38:55","100150","high","Lateral movement — SMB","admin-pc","10.0.0.22","10"),
        ("03:30:12","100400","high","Data exfiltration — large upload","backup-srv","10.0.0.50","9"),
        ("03:22:44","100050","medium","Failed auth — root account","mail-srv","192.0.2.15","7"),
        ("03:18:33","100600","medium","New process — unusual parent","workstation-05","10.0.1.33","7"),
        ("03:14:20","100700","medium","Registry modification","workstation-12","10.0.1.44","6"),
        ("03:11:05","100800","low","Port scan detected","firewall","198.51.100.5","5"),
        ("03:08:47","100900","low","Repeated login attempts","vpn-gw","203.0.113.22","4"),
    ]
    for i,row in enumerate(alert_rows):
        ts,rid,sev,desc,agent,src,lvl = row
        yp = 0.925 - i*0.089
        c = SEV_COLORS.get(sev,TXT3)
        if i%2==0:
            rb = FancyBboxPatch((0.005,yp-0.038),0.99,0.075,boxstyle="square,pad=0",
                                facecolor=B1,edgecolor='none',alpha=0.35,
                                transform=ax_table.transAxes)
            ax_table.add_patch(rb)
        vals = [ts,rid,"",desc,agent,src,lvl]
        vc   = [TXT3,TXT2,c,TXT,CYAN,ORANGE,c]
        for v,x,col in zip(vals,col_x,vc):
            ax_table.text(x,yp,v,va='center',fontsize=4.5,color=col,
                          fontfamily='monospace',transform=ax_table.transAxes)
        # Severity badge
        bp = FancyBboxPatch((0.17,yp-0.028),0.1,0.055,boxstyle="round,pad=0.01",
                            facecolor=c,edgecolor=c,linewidth=0,alpha=0.2,
                            transform=ax_table.transAxes)
        ax_table.add_patch(bp)
        ax_table.text(0.22,yp,sev.upper(),ha='center',va='center',fontsize=3.8,
                      color=c,fontweight='bold',transform=ax_table.transAxes)

    # Pagination
    ax_table.text(0.5,0.025,"← Prev   Page 1 of 57   Next →",ha='center',va='center',
                  fontsize=5.5,color=TXT3,transform=ax_table.transAxes)

    plt.savefig("screenshot_alerts.png", dpi=150, bbox_inches='tight',
                facecolor=BG, edgecolor='none')
    plt.close()
    print("screenshot_alerts.png saved")


if __name__ == "__main__":
    gen_dashboard()
    gen_alerts()
    gen_mitre()
    gen_investigation()
    gen_ueba()
    gen_darksoc()
    print("\nAll screenshots generated.")
