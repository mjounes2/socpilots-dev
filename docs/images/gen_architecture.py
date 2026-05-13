#!/usr/bin/env python3
"""Generate SOCPilots architecture diagram PNG."""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patheffects as pe
import numpy as np

# ── Color palette (dark-theme, matching SOCPilots UI)
BG        = "#0a1628"
BG2       = "#0f1e35"
B1        = "#1a2f4a"
B2        = "#244060"
CYAN      = "#00e5ff"
CYAN_DIM  = "#00b8d4"
GREEN     = "#00e676"
ORANGE    = "#ff9800"
RED       = "#ff1744"
PURPLE    = "#7c4dff"
YELLOW    = "#ffc107"
TXT       = "#e8f4fd"
TXT2      = "#8ab0d0"
TXT3      = "#4a6f8a"

fig, ax = plt.subplots(figsize=(22, 15))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 22)
ax.set_ylim(0, 15)
ax.axis('off')

# ─────────────────────────────────────────
# Helper: draw a service box
# ─────────────────────────────────────────
def box(ax, x, y, w, h, label, sublabel="", color=CYAN, alpha=0.15, icon=""):
    bg = FancyBboxPatch((x, y), w, h,
                        boxstyle="round,pad=0.05",
                        facecolor=color, alpha=alpha,
                        edgecolor=color, linewidth=1.5)
    ax.add_patch(bg)
    yc = y + h / 2
    if sublabel:
        ax.text(x + w/2, yc + 0.12, (icon + " " if icon else "") + label,
                ha='center', va='center', fontsize=8.5, fontweight='bold',
                color=color, fontfamily='monospace')
        ax.text(x + w/2, yc - 0.18, sublabel,
                ha='center', va='center', fontsize=6.5, color=TXT2, fontstyle='italic')
    else:
        ax.text(x + w/2, yc, (icon + " " if icon else "") + label,
                ha='center', va='center', fontsize=8.5, fontweight='bold',
                color=color, fontfamily='monospace')

def arrow(ax, x1, y1, x2, y2, color=TXT3, style='->', lw=1.2, label=""):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle=style, color=color, lw=lw,
                                connectionstyle="arc3,rad=0.0"))
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx, my + 0.08, label, ha='center', va='bottom',
                fontsize=5.5, color=TXT3)

def zone(ax, x, y, w, h, label, color=B2, label_color=TXT2):
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle="round,pad=0.1",
                          facecolor=color, alpha=0.18,
                          edgecolor=color, linewidth=0.8, linestyle='--')
    ax.add_patch(rect)
    ax.text(x + 0.15, y + h - 0.18, label,
            ha='left', va='top', fontsize=7, color=label_color,
            fontweight='bold', alpha=0.7)

# ─────────────────────────────────────────
# Title
# ─────────────────────────────────────────
ax.text(11, 14.5, "SOCPilots  — System Architecture",
        ha='center', va='center', fontsize=18, fontweight='bold',
        color=CYAN, fontfamily='monospace')
ax.text(11, 14.0, "Enterprise Security Operations Center Platform  |  Docker Compose  |  Single-Server Deployment",
        ha='center', va='center', fontsize=9, color=TXT2)

# Horizontal rule
ax.plot([0.3, 21.7], [13.7, 13.7], color=B2, lw=1)

# ─────────────────────────────────────────
# Zone: External
# ─────────────────────────────────────────
zone(ax, 0.3, 12.6, 21.4, 1.0, "External Access", color=CYAN, label_color=CYAN)
ax.text(2.0, 13.15, "Browser / Analyst", ha='center', va='center', fontsize=8, color=TXT, fontweight='bold')
arrow(ax, 3.2, 13.1, 5.2, 13.1, color=CYAN, lw=1.5, label=":443 HTTPS")
ax.text(14.5, 13.15, "Wazuh Instance (external)", ha='center', va='center', fontsize=8, color=ORANGE, fontweight='bold')
ax.text(14.5, 12.82, "Manager :55000  |  OpenSearch :9200", ha='center', va='center', fontsize=6.5, color=TXT2)
ax.text(19.5, 13.15, "TheHive (external)", ha='center', va='center', fontsize=8, color=PURPLE, fontweight='bold')
ax.text(19.5, 12.82, "REST API  |  :9000 / :443", ha='center', va='center', fontsize=6.5, color=TXT2)

# ─────────────────────────────────────────
# Zone: Docker Network soc
# ─────────────────────────────────────────
zone(ax, 0.3, 0.3, 21.4, 12.1, "Docker Network: soc (bridge)", color=B1, label_color=TXT3)

# ─────────────────────────────────────────
# nginx + webapp (row 1)
# ─────────────────────────────────────────
box(ax, 4.8, 11.5, 2.8, 0.9, "nginx", ":80 / :443", color=GREEN)
box(ax, 8.2, 11.5, 2.8, 0.9, "webapp", "Express SPA :3000", color=CYAN)

arrow(ax, 7.6, 11.95, 8.2, 11.95, color=CYAN, lw=1.5, label="proxy")
arrow(ax, 11.0, 11.95, 11.6, 11.95, color=CYAN, lw=1.5)

# n8n
box(ax, 4.8, 10.0, 2.8, 0.9, "n8n", "Automation :5678", color=YELLOW)
arrow(ax, 6.2, 11.5, 6.2, 10.9, color=YELLOW, lw=1, label="workflows")

# ─────────────────────────────────────────
# Core AI services (row 2)
# ─────────────────────────────────────────
zone(ax, 0.4, 8.6, 21.2, 1.5, "AI  &  Knowledge Layer", color=PURPLE, label_color=PURPLE)

box(ax, 0.6, 8.9, 3.0, 0.9, "langchain-agent", "FastAPI / ReAct :8001", color=PURPLE)
box(ax, 4.0, 8.9, 2.8, 0.9, "rag-retrieval", "Flask / BGE :5005", color=PURPLE)
box(ax, 7.1, 8.9, 3.2, 0.9, "knowledge-ingestion", "Flask / OCR :5004", color=CYAN_DIM)
box(ax, 10.6, 8.9, 2.5, 0.9, "scanner", "nmap / Node :7777", color=TXT3)
box(ax, 13.4, 8.9, 2.5, 0.9, "asset-scan", "Flask / nmap :5003", color=TXT3)

arrow(ax, 9.6, 11.5, 1.6, 9.8, color=PURPLE, lw=1.2, label="investigate")
arrow(ax, 9.6, 11.5, 5.4, 9.8, color=PURPLE, lw=1.0, label="rag")
arrow(ax, 9.6, 11.5, 8.7, 9.8, color=CYAN_DIM, lw=1.0, label="evidence")
arrow(ax, 9.6, 11.5, 11.85, 9.8, color=TXT3, lw=0.8, label="scan")
arrow(ax, 9.6, 11.5, 14.65, 9.8, color=TXT3, lw=0.8, label="assets")

# ─────────────────────────────────────────
# MCP bridges (row 3)
# ─────────────────────────────────────────
zone(ax, 0.4, 6.9, 10.0, 1.5, "MCP Bridges  (JSON-RPC 2.0)", color=ORANGE, label_color=ORANGE)

box(ax, 0.6, 7.2, 3.5, 0.9, "mcp-wazuh", "Python MCP :3001", color=ORANGE)
box(ax, 4.4, 7.2, 3.0, 0.9, "thehive-mcp", "Go MCP :8080", color=PURPLE)

arrow(ax, 6.2, 10.0, 2.35, 8.1, color=ORANGE, lw=1.0, label="active-response")
arrow(ax, 6.2, 10.0, 5.9, 8.1, color=PURPLE, lw=1.0, label="cases")
arrow(ax, 1.6, 9.8, 2.35, 8.1, color=ORANGE, lw=0.8)

# External arrows from MCP
arrow(ax, 2.35, 7.2, 14.5, 12.65, color=ORANGE, lw=1.0, label="Wazuh REST")
arrow(ax, 5.9, 7.2, 19.5, 12.65, color=PURPLE, lw=1.0, label="TheHive REST")

# ─────────────────────────────────────────
# Data stores (row 3 right + row 4)
# ─────────────────────────────────────────
zone(ax, 10.5, 6.2, 11.2, 6.1, "Data Stores", color=GREEN, label_color=GREEN)

box(ax, 10.7, 9.8, 2.5, 1.0, "postgres", ":5432", color=GREEN)
box(ax, 13.5, 9.8, 2.5, 1.0, "qdrant", "Vector DB :6333", color=CYAN)
box(ax, 16.3, 9.8, 2.5, 1.0, "redis", "IOC Cache :6379", color=RED)
box(ax, 19.1, 9.8, 2.3, 1.0, "neo4j", "UEBA :7687", color=YELLOW)

arrow(ax, 9.6, 11.5, 11.95, 10.8, color=GREEN, lw=0.8, label="SQL")
arrow(ax, 8.7, 9.8, 14.75, 10.8, color=CYAN, lw=0.8, label="embed")
arrow(ax, 1.6, 9.8, 17.55, 10.8, color=RED, lw=0.7, label="cache")
arrow(ax, 9.6, 11.5, 20.25, 10.8, color=YELLOW, lw=0.8, label="UEBA")

# OpenSearch arrow from webapp
arrow(ax, 9.6, 11.5, 14.5, 12.65, color=ORANGE, lw=0.8, label="alerts query")

# ─────────────────────────────────────────
# Legend
# ─────────────────────────────────────────
lx, ly = 10.7, 8.5
legend_items = [
    (CYAN,   "SOCPilots Core"),
    (PURPLE, "AI / MCP Layer"),
    (GREEN,  "Data Stores"),
    (ORANGE, "Wazuh Bridge"),
    (YELLOW, "Automation / UEBA"),
    (RED,    "Cache"),
    (TXT3,   "Scan Services"),
]
ax.text(lx, ly, "Legend", fontsize=7.5, color=TXT2, fontweight='bold', va='top')
for i, (c, lbl) in enumerate(legend_items):
    xi = lx + (i % 4) * 2.7
    yi = ly - 0.35 - (i // 4) * 0.4
    patch = FancyBboxPatch((xi, yi - 0.12), 0.22, 0.22,
                           boxstyle="round,pad=0.02",
                           facecolor=c, edgecolor=c, alpha=0.7)
    ax.add_patch(patch)
    ax.text(xi + 0.32, yi, lbl, fontsize=6.5, color=TXT2, va='center')

# Version stamp
ax.text(21.6, 0.15, "v2025 · SOCPilots", ha='right', va='bottom',
        fontsize=6.5, color=TXT3, fontstyle='italic')

plt.tight_layout(pad=0.2)
plt.savefig("architecture.png", dpi=180, bbox_inches='tight',
            facecolor=BG, edgecolor='none')
plt.close()
print("architecture.png saved")
