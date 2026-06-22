#!/usr/bin/env python3
#
# Argus — monitoramento de superfície de ataque
# Copyright (C) 2026  Bruno Santos
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
reporter.py — Gerador de relatórios HTML compartilhado

Usado por monitor.py e submonitor.py.
Centraliza CSS, JS utilitários e geração de HTML para manutenção única.

Uso:
    from reporter import generate_monitor_report, generate_submonitor_report

    generate_monitor_report(novos, reincidentes, corrigidos,
                            output_path="monitor_report.html",
                            threatintel_available=True)

    generate_submonitor_report(novos, reincidentes, removidos,
                               output_path="submonitor_report.html",
                               threatintel_available=True)
"""

import base64
import datetime
import html
import json
from pathlib import Path

# ============================================================
# UTILITÁRIOS COMPARTILHADOS
# ============================================================


def _abuse_to_js(abuse: dict | None) -> dict:
    """Normaliza dict de reputação AbuseIPDB para serialização JS segura."""
    if not abuse:
        return {
            "score": -1, "country": "", "isp": "",
            "usage_type": "", "is_tor": False,
            "total_reports": 0, "last_reported_at": "",
            "source": "N/A",
        }
    return {
        "score":            int(abuse.get("abuse_confidence_score", -1)
                                if abuse.get("abuse_confidence_score") is not None else -1),
        "country":          str(abuse.get("country_code",      "") or ""),
        "isp":              str(abuse.get("isp",               "") or ""),
        "usage_type":       str(abuse.get("usage_type",        "") or ""),
        "is_tor":           bool(abuse.get("is_tor",           False)),
        "total_reports":    int(abuse.get("total_reports",     0) or 0),
        "last_reported_at": str(abuse.get("last_reported_at",  "") or ""),
        "source":           str(abuse.get("source",            "") or ""),
    }


def _urlscan_to_js(us: dict | None) -> dict:
    """Normaliza dict do urlscan.io para serialização JS segura."""
    if not us:
        return {"seen": False, "server": "", "ip": "", "asnname": "",
                "country": "", "scan_uuid": "", "report_url": "", "screenshot": ""}
    return {
        "seen":       bool(us.get("seen", False)),
        "server":     str(us.get("server",     "") or ""),
        "ip":         str(us.get("ip",         "") or ""),
        "asnname":    str(us.get("asnname",    "") or ""),
        "country":    str(us.get("country",    "") or ""),
        "scan_uuid":  str(us.get("scan_uuid",  "") or ""),
        "report_url": str(us.get("report_url", "") or ""),
        "screenshot": str(us.get("screenshot", "") or ""),
    }


def _internetdb_to_js(idb: dict | None) -> dict:
    """Normaliza o intel do Shodan InternetDB (vulns/tags/ports) para JS seguro."""
    if not idb:
        return {"vuln_count": 0, "vulns": [], "tags": [], "ports": []}
    return {
        "vuln_count": int(idb.get("vuln_count", 0) or 0),
        "vulns": [str(v) for v in (idb.get("vulns") or [])][:50],
        "tags":  [str(t) for t in (idb.get("tags") or [])][:20],
        "ports": [int(p) for p in (idb.get("ports") or []) if str(p).strip().isdigit()][:60],
    }


def _kev_to_js(kev: dict | None) -> dict:
    """Normaliza o intel CISA KEV (CVEs exploradas in-the-wild) para JS seguro."""
    if not kev:
        return {"kev_count": 0, "kev_cves": []}
    return {
        "kev_count": int(kev.get("kev_count", 0) or 0),
        "kev_cves": [str(c) for c in (kev.get("kev_cves") or [])][:50],
    }


def _nvd_to_js(nvd: dict | None) -> dict:
    """Normaliza o intel NVD (CVSS oficial por CVE) para JS seguro."""
    if not nvd:
        return {"max_cvss": 0, "max_severity": "", "scores": {}}
    scores = {}
    for c, s in (nvd.get("scores") or {}).items():
        try:
            scores[str(c)] = float(s)
        except (TypeError, ValueError):
            pass
    return {
        "max_cvss": float(nvd.get("max_cvss", 0) or 0),
        "max_severity": str(nvd.get("max_severity", "") or ""),
        "scores": dict(list(scores.items())[:50]),
    }


# ============================================================
# CSS COMPARTILHADO
# ============================================================

def _common_css() -> str:
    return """
  /* JetBrains Mono (OFL-1.1) — self-hosted, offline-safe; dá caráter técnico aos dados
     (IP/porta/CVE/code). Subset latino, 400+700. font-display:swap cai p/ system até carregar. */
  @font-face { font-family:'JetBrains Mono'; font-style:normal; font-weight:400; font-display:swap;
    src:url('/assets/fonts/jetbrains-mono-400.woff2') format('woff2'); }
  @font-face { font-family:'JetBrains Mono'; font-style:normal; font-weight:700; font-display:swap;
    src:url('/assets/fonts/jetbrains-mono-700.woff2') format('woff2'); }
  *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
  :root {
    --bg:#070c16; --bg-grad:radial-gradient(1150px 580px at 78% -12%, #122747 0%, #070c16 58%);
    --surface:#0f1827; --surface-2:#152237; --border:#223450; --border-2:#324563;
    --text:#e8f0fb; --muted:#a7b4cc; --faint:#7886a3; --accent:#33a3ef; --accent-2:#818cf8;
    --steel:#cbdaec; --steel-2:#9db2cd;
    --red:#f43f5e; --orange:#fb923c; --yellow:#fbbf24; --green:#34d399; --pink:#f472b6;
    --radius:10px; --radius-sm:7px;
    --shadow:0 10px 30px -16px rgba(0,0,0,.7);
    --font:'Inter','Segoe UI',system-ui,-apple-system,Arial,sans-serif;
    --mono:'JetBrains Mono',ui-monospace,'SFMono-Regular',Menlo,Consolas,monospace;
  }
  body { background:var(--bg); background-image:var(--bg-grad); background-attachment:fixed;
         color:var(--text); font-family:var(--font); font-size:14px; padding:0; -webkit-font-smoothing:antialiased; }
  .wrap { max-width:1560px; margin:0 auto; padding:22px 26px 56px; }
  code, .mono { font-family:var(--mono); }
  a { color:var(--accent); }
  abbr[title] { text-decoration:underline dotted; text-underline-offset:2px; cursor:help; }
  /* Skip link (acessibilidade): oculto até receber foco via teclado. */
  .skip-link { position:absolute; left:-9999px; top:0; z-index:100; background:var(--accent); color:#04121f;
       padding:10px 16px; border-radius:0 0 8px 0; font-weight:700; font-size:13px; text-decoration:none; }
  .skip-link:focus { left:0; }
  /* Conteúdo só para leitores de tela (visualmente oculto, acessível). */
  .sr-only { position:absolute!important; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden;
       clip:rect(0,0,0,0); white-space:nowrap; border:0; }

  /* ── Barra de progresso de navegação (feedback de carregamento) ── */
  #navprog { position:fixed; top:0; left:0; height:3px; width:0; z-index:60;
             background:linear-gradient(90deg,var(--accent),var(--accent-2)); box-shadow:0 0 8px var(--accent);
             opacity:0; pointer-events:none; }
  #navprog.go { width:92%; opacity:1; transition:width 8s cubic-bezier(.1,.7,.1,1); }

  /* ── Top bar / navegação ─────────────────────────────── */
  .topbar { position:sticky; top:0; z-index:20; display:flex; align-items:center; gap:22px;
            padding:0 26px; height:58px; background:rgba(8,12,22,.85); backdrop-filter:blur(10px);
            border-bottom:1px solid var(--border); }
  .brand { display:flex; align-items:center; gap:11px; white-space:nowrap; text-decoration:none; color:inherit; cursor:pointer; }
  .brand:hover .logo { filter:drop-shadow(0 0 12px rgba(51,163,239,.5)); }
  .brand .logo { width:32px; height:32px; display:block; filter:drop-shadow(0 0 10px rgba(51,163,239,.28)); }
  .brand .bwrap { display:flex; flex-direction:column; line-height:1.08; }
  .brand .bn { font-weight:800; font-size:16px; letter-spacing:2.4px;
               background:linear-gradient(180deg,var(--steel) 30%,var(--steel-2)); -webkit-background-clip:text;
               background-clip:text; color:transparent; }
  .brand .sub { color:var(--accent); font-weight:700; font-size:10px; text-transform:uppercase; letter-spacing:1.6px; opacity:.95; }
  .nav { display:flex; gap:4px; flex:1; flex-wrap:wrap; }
  .nav a { display:inline-flex; align-items:center; gap:7px; padding:8px 13px; border-radius:var(--radius-sm);
           color:var(--muted); text-decoration:none; font-size:13px; font-weight:600; transition:.15s; }
  .nav a:hover { color:var(--text); background:var(--surface); }
  .nav a.active { color:var(--accent); font-weight:700; background:rgba(51,163,239,.16);
                  box-shadow:inset 0 0 0 1px rgba(51,163,239,.4), inset 0 -2px 0 var(--accent); }
  body.light .nav a.active { background:rgba(23,105,192,.14); box-shadow:inset 0 0 0 1px rgba(23,105,192,.45), inset 0 -2px 0 var(--accent); }
  .nav a svg { width:15px; height:15px; opacity:.85; }
  /* Botão hambúrguer — só aparece no mobile (ver media query no fim do CSS). */
  .nav-toggle { display:none; flex:none; width:44px; height:44px; align-items:center; justify-content:center;
       border:1px solid var(--border); background:var(--surface); color:var(--text); border-radius:var(--radius-sm); cursor:pointer; }
  .nav-toggle svg { width:20px; height:20px; }
  .nav-toggle:hover { color:var(--accent); border-color:var(--accent); }
  .topbar-meta { color:var(--faint); font-size:11.5px; text-align:right; white-space:nowrap; }
  .topbar-meta b { color:var(--muted); font-weight:600; }
  /* ── Breadcrumb (trilha de localização) ──────────────── */
  .breadcrumb { display:flex; align-items:center; gap:7px; padding:9px 26px 0; font-size:12px; color:var(--muted); flex-wrap:wrap; }
  .breadcrumb a { color:var(--muted); text-decoration:none; }
  .breadcrumb a:hover { color:var(--accent); }
  .breadcrumb .sep { color:var(--faint); }
  .breadcrumb .cur { color:var(--text); font-weight:600; }

  /* ── Cabeçalho da página ─────────────────────────────── */
  .page-head { display:flex; align-items:flex-end; justify-content:space-between; gap:14px; flex-wrap:wrap; margin:6px 0 18px; }
  .page-title { font-size:21px; font-weight:800; letter-spacing:.2px; display:flex; align-items:center; gap:10px; }
  .page-title .chip { font-size:11px; font-weight:600; color:var(--muted); background:var(--surface);
                      border:1px solid var(--border); border-radius:999px; padding:3px 10px; letter-spacing:.3px; }
  .page-sub { color:var(--muted); font-size:12.5px; margin-top:5px; }
  .actions { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .actions select { background:rgba(51,163,239,.10); color:#bae6fd; border:1px solid rgba(51,163,239,.3);
                    border-radius:var(--radius-sm); padding:8px 11px; font-size:13px; font-weight:600; cursor:pointer; outline:none; }
  .actions select:focus { box-shadow:0 0 0 3px rgba(51,163,239,.12); }

  /* ── Painel de resumo: KPIs + donut ──────────────────── */
  .summary { display:grid; grid-template-columns:1fr 260px; gap:16px; margin-bottom:20px; }
  @media (max-width:920px){ .summary { grid-template-columns:1fr; } }
  .panel { background:linear-gradient(180deg,var(--surface),var(--surface-2)); border:1px solid var(--border);
           border-radius:var(--radius); box-shadow:var(--shadow); }
  .kpi-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(118px,1fr)); gap:1px; background:var(--border);
              border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; }
  .kpi { background:linear-gradient(180deg,var(--surface),var(--surface-2)); padding:15px 16px 15px 18px; position:relative; }
  /* O número é o herói: cor sólida de alto contraste (--text). A severidade é
     comunicada pela barra lateral colorida (acento), não pela cor do número. */
  .kpi::before { content:''; position:absolute; left:0; top:12px; bottom:12px; width:4px; border-radius:0 3px 3px 0; background:var(--border-2); }
  .kpi .v { font-size:25px; font-weight:800; line-height:1; letter-spacing:-.5px; color:var(--text); }
  .kpi .l { font-size:11.5px; color:var(--muted); margin-top:6px; text-transform:uppercase; letter-spacing:.5px; }
  .kpi.sev-crit::before{ background:var(--red); width:5px; }
  .kpi.sev-alto::before{ background:var(--orange); }
  .kpi.sev-med::before{ background:var(--yellow); }
  .kpi.sev-novo::before{ background:var(--accent); }
  .kpi.sev-rein::before{ background:var(--accent-2); }
  .kpi.sev-abus::before{ background:var(--pink); }

  .donut-card { padding:16px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:10px; }
  .donut-card h2 { font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.9px; align-self:flex-start; font-weight:700; }
  .donut-flex { display:flex; align-items:center; gap:16px; width:100%; }
  .donut { width:120px; height:120px; flex:none; }
  .donut .tot { font-size:24px; font-weight:800; fill:var(--text); }
  .donut .totl { font-size:9.5px; fill:var(--muted); letter-spacing:1px; }
  .legend { display:flex; flex-direction:column; gap:7px; font-size:12px; }
  .legend-item { display:flex; align-items:center; gap:8px; color:var(--muted); }
  .legend-item .dot { width:9px; height:9px; border-radius:3px; flex:none; }
  .legend-item b { color:var(--text); font-variant-numeric:tabular-nums; margin-left:auto; padding-left:14px; }

  /* ── Toolbar / filtros ───────────────────────────────── */
  .toolbar { display:flex; align-items:center; gap:9px; margin-bottom:12px; flex-wrap:wrap; }
  .toolbar input[type=text], .toolbar select {
    background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-sm);
    color:var(--text); padding:8px 11px; outline:none; font-size:13px; }
  .toolbar input[type=text] { flex:1; min-width:220px; }
  .toolbar input[type=text]:focus, .toolbar select:focus { border-color:var(--accent); box-shadow:0 0 0 3px rgba(51,163,239,.12); }
  .toolbar select { cursor:pointer; }
  .btn { padding:8px 14px; border-radius:var(--radius-sm); border:1px solid transparent; font-size:13px; font-weight:600;
         cursor:pointer; display:inline-flex; align-items:center; gap:7px; transition:.15s; }
  .btn:hover { transform:translateY(-1px); }
  /* CTAs de exportação: fundo sólido de alto contraste (texto branco ≥4.5:1). */
  .btn-pdf { background:#4f46e5; color:#fff; border-color:#4f46e5; }
  .btn-pdf:hover { background:#4338ca; }
  .btn-csv { background:#047857; color:#fff; border-color:#047857; }
  .btn-csv:hover { background:#036b4d; }
  .btn-clr { background:var(--surface); color:var(--muted); border-color:var(--border); }

  /* ── "Mais filtros" (agrupa filtros secundários) ────────── */
  .morefilters { position:relative; display:inline-block; }
  .morefilters > summary { list-style:none; cursor:pointer; padding:8px 13px; border-radius:var(--radius-sm);
       border:1px solid var(--border); background:var(--surface); color:var(--muted); font-size:13px; font-weight:600;
       display:inline-flex; align-items:center; gap:7px; user-select:none; }
  .morefilters > summary::-webkit-details-marker { display:none; }
  .morefilters > summary::marker { content:""; }
  .morefilters[open] > summary { color:var(--accent); border-color:var(--accent); }
  .morefilters-body { position:absolute; z-index:40; top:calc(100% + 6px); left:0; min-width:240px;
       background:var(--surface-2,#0e1727); border:1px solid var(--border); border-radius:var(--radius);
       padding:10px; box-shadow:var(--shadow); display:flex; flex-direction:column; gap:8px; }
  .morefilters-body::before { content:"Filtros adicionais"; font-size:10px; text-transform:uppercase;
       letter-spacing:.6px; color:var(--faint); }
  .morefilters-body select { width:100%; }

  /* ── Menu "Colunas" (mostrar/ocultar) ───────────────────── */
  .colmenu { position:relative; display:inline-block; }
  .colmenu > summary { list-style:none; cursor:pointer; padding:8px 13px; border-radius:var(--radius-sm);
       border:1px solid var(--border); background:var(--surface); color:var(--muted); font-size:13px; font-weight:600;
       display:inline-flex; align-items:center; gap:7px; user-select:none; }
  .colmenu > summary::-webkit-details-marker { display:none; }
  .colmenu > summary::marker { content:""; }
  .colmenu[open] > summary { color:var(--accent); border-color:var(--accent); }
  .colmenu-body { position:absolute; z-index:40; top:calc(100% + 6px); right:0; min-width:210px; max-height:340px; overflow:auto;
       background:var(--surface-2,#0e1727); border:1px solid var(--border); border-radius:var(--radius);
       padding:7px; box-shadow:var(--shadow,0 12px 32px rgba(0,0,0,.5)); display:flex; flex-direction:column; gap:1px; }
  .colmenu-body::before { content:"Exibir colunas"; display:block; font-size:10px; text-transform:uppercase;
       letter-spacing:.6px; color:var(--faint); padding:3px 7px 6px; }
  .colmenu-body label { display:flex; align-items:center; gap:8px; padding:5px 7px; font-size:12.5px;
       color:var(--text); cursor:pointer; border-radius:6px; white-space:nowrap; }
  .colmenu-body label:hover { background:var(--surface); }
  .colmenu-body input[type=checkbox] { accent-color:var(--accent); width:14px; height:14px; cursor:pointer; }

  .tabs { display:flex; gap:4px; margin-bottom:14px; border-bottom:1px solid var(--border); }
  .tab { padding:9px 16px; border-radius:var(--radius-sm) var(--radius-sm) 0 0; border:1px solid transparent; border-bottom:none;
         cursor:pointer; font-weight:600; font-size:13px; color:var(--muted); background:transparent; transition:.15s; margin-bottom:-1px; }
  .tab:hover { color:var(--text); }
  .tab.active { color:var(--accent); background:var(--surface); border-color:var(--border); }
  .tab .badge { display:inline-block; background:var(--bg); color:var(--steel-2); border-radius:999px; padding:1px 8px; font-size:11px; margin-left:6px; }
  .badge { display:inline-block; background:var(--border); color:var(--steel-2); border-radius:999px; padding:1px 8px; font-size:11px; margin-left:4px; }

  /* ── Tabela ──────────────────────────────────────────── */
  /* Indicador de scroll horizontal: a borda recebe um realce + sombra quando há
     colunas fora da área visível (classes .sx-left/.sx-right setadas por JS). */
  .tbl-wrap { overflow-x:auto; border:1px solid var(--border); border-radius:var(--radius);
              background:var(--surface); position:relative; transition:box-shadow .15s, border-color .15s; }
  .tbl-wrap.sx-right { border-right-color:var(--accent);
       box-shadow:inset -26px 0 22px -22px rgba(2,6,14,.9); }
  .tbl-wrap.sx-left  { border-left-color:var(--accent);
       box-shadow:inset 26px 0 22px -22px rgba(2,6,14,.9); }
  .tbl-wrap.sx-left.sx-right { border-left-color:var(--accent); border-right-color:var(--accent);
       box-shadow:inset 26px 0 22px -22px rgba(2,6,14,.9), inset -26px 0 22px -22px rgba(2,6,14,.9); }
  /* Dica textual "role para ver mais colunas" — injetada e alternada por JS. */
  .scroll-hint { display:none; font-size:11px; font-weight:600; color:var(--accent); margin:6px 2px 0; align-items:center; gap:6px; }
  .scroll-hint.show { display:inline-flex; }
  table { width:100%; border-collapse:separate; border-spacing:0; font-size:12.5px; }
  /* Em telas estreitas, a tabela de dados rola na horizontal (não esmaga colunas). */
  .tbl-wrap table { min-width:680px; }
  th { background:#0e1727; color:var(--muted); padding:11px 12px; text-align:left; white-space:nowrap;
       cursor:pointer; user-select:none; font-size:11px;
       text-transform:uppercase; letter-spacing:.5px; border-bottom:1px solid var(--border-2); }
  th:hover { color:var(--accent); }
  th .si { margin-left:5px; color:var(--muted); font-size:13px; vertical-align:middle; }
  th:hover .si { color:var(--accent); }
  td { padding:9px 12px; vertical-align:middle; border-bottom:1px solid rgba(35,49,76,.6); white-space:nowrap; }
  tbody tr:nth-child(even) td { background:rgba(255,255,255,.012); }
  tbody tr:hover td { background:rgba(51,163,239,.06); }
  td code { font-size:12px; color:#cde7ff; }
  /* acento de severidade na 1ª célula da linha */
  tbody tr.r-CRITICO td { background:rgba(244,63,94,.05); }
  tbody tr.r-CRITICO:hover td { background:rgba(244,63,94,.11); }
  tr.r-CRITICO td:first-child { box-shadow:inset 3px 0 0 var(--red); }
  tr.r-ALTO    td:first-child { box-shadow:inset 3px 0 0 var(--orange); }
  tr.r-MEDIO   td:first-child { box-shadow:inset 3px 0 0 var(--yellow); }
  tr.r-BAIXO   td:first-child { box-shadow:inset 3px 0 0 var(--green); }
  tr.r-INFO    td:first-child { box-shadow:inset 3px 0 0 var(--border-2); }

  .camp-badge { background:rgba(129,140,248,.16); color:#c7d2fe; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .ip-PUBLICO { background:rgba(51,163,239,.14); color:#7dd3fc; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .ip-PRIVADO { background:rgba(52,211,153,.14); color:#6ee7b7; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }

  .risk-CRITICO { color:var(--red);    font-weight:800; }
  .risk-ALTO    { color:var(--orange); font-weight:800; }
  .risk-MEDIO   { color:var(--yellow); font-weight:700; }
  .risk-BAIXO   { color:var(--green); }
  .risk-INFO    { color:var(--muted); }
  /* Acessibilidade (daltonismo): forma distinta por severidade, além da cor.
     Cada nível ganha um símbolo geométrico próprio — não depende só de cor (WCAG 1.4.1). */
  .risk-CRITICO::before, .r-critico::before { content:"\\25C6 "; font-size:.85em; }  /* losango */
  .risk-ALTO::before,    .r-alto::before    { content:"\\25B2 "; font-size:.8em; }   /* triângulo */
  .risk-MEDIO::before,   .r-medio::before   { content:"\\25A0 "; font-size:.8em; }   /* quadrado */
  .risk-BAIXO::before,   .r-baixo::before   { content:"\\25CF "; font-size:.78em; }  /* círculo */
  .risk-INFO::before                         { content:"\\2014 "; }                   /* traço */
  .status-NOVO        { color:var(--accent); font-weight:700; }
  .status-REINCIDENTE { color:var(--accent-2); font-weight:700; }
  .status-CORRIGIDO   { color:var(--green); font-weight:600; }
  .status-RESSURGIDO  { color:var(--orange); font-weight:700; }
  .status-FECHADO     { color:var(--muted); }
  .status-REMOVIDO    { color:var(--muted); }
  .status-RECONHECIDO { color:#c4b5fd; font-weight:700; background:rgba(167,139,250,.15);
       border:1px solid rgba(167,139,250,.34); border-radius:6px; padding:2px 8px; font-size:11px; white-space:nowrap; }
  tr.ack td:first-child { box-shadow:inset 3px 0 0 #a78bfa !important; }
  tr.ack td { background:rgba(167,139,250,.04); }
  .ack-reason { color:var(--muted); font-size:11.5px; font-style:italic; max-width:240px;
       overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:inline-block; vertical-align:bottom; }
  .ack-reason::before { content:"\\201C"; } .ack-reason::after { content:"\\201D"; }
  .cve-badge { background:rgba(244,63,94,.16); color:#fda4af; border:1px solid rgba(244,63,94,.34);
       border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; white-space:nowrap; cursor:help; }
  /* KEV: exploração CONFIRMADA in-the-wild (CISA) — selo sólido, mais forte que o CVE */
  .kev-badge { background:var(--red); color:#fff; border-radius:6px; padding:2px 7px; font-size:10.5px;
       font-weight:800; letter-spacing:.6px; white-space:nowrap; cursor:help; }
  .tag-chip { background:var(--surface); color:var(--muted); border:1px solid var(--border);
       border-radius:5px; padding:1px 6px; font-size:10px; margin-left:3px; }

  .score-na       { color:var(--muted); font-size:11px; }
  .score-clean    { color:var(--green);  font-weight:600; }
  .score-low      { color:var(--yellow); font-weight:600; }
  .score-medium   { color:var(--orange); font-weight:700; }
  .score-high     { color:var(--red);    font-weight:700; }
  .score-critical { color:#fff; background:var(--red); border-radius:6px; padding:2px 8px; font-weight:700; font-size:12px;
                    animation:pulse 1.2s ease-in-out infinite; }
  .tor-badge { background:rgba(129,140,248,.2); color:#c7d2fe; border-radius:5px; padding:1px 6px; font-size:10px; font-weight:700; margin-left:4px; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.55} }

  .dnssec-on  { background:rgba(52,211,153,.18); color:#8af0c6; border:1px solid rgba(52,211,153,.45); border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .dnssec-off { background:rgba(244,63,94,.12); color:#fda4af; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:600; }
  .ssl-ok     { background:rgba(52,211,153,.14); color:#6ee7b7; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .ssl-warn   { background:rgba(251,191,36,.14); color:#fcd34d; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .ssl-bad    { background:rgba(244,63,94,.16); color:#fda4af; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .ssl-none   { color:var(--faint); font-size:11px; }
  .origem-crtsh    { background:rgba(51,163,239,.14); color:#7dd3fc; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .origem-urlscan  { background:rgba(168,85,247,.18); color:#d8b4fe; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .origem-wordlist { background:var(--surface-2); color:var(--muted); border-radius:6px; padding:2px 8px; font-size:11px; border:1px solid var(--border); }
  .us-seen   { background:rgba(168,85,247,.18); color:#d8b4fe; border-radius:6px; padding:2px 6px; font-size:11px; font-weight:700; }
  .us-link   { color:#7dd3fc; text-decoration:none; font-size:11px; border:1px solid var(--border); border-radius:5px; padding:1px 5px; margin-left:3px; }
  .us-link:hover { background:var(--surface-2); }
  .whois-novo   { background:rgba(244,63,94,.16); color:#fda4af; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; animation:pulse 2s infinite; }
  .whois-recente{ background:rgba(251,191,36,.14); color:#fcd34d; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:600; }
  .whois-estab  { background:rgba(52,211,153,.14); color:#6ee7b7; border-radius:6px; padding:2px 8px; font-size:11px; }
  .whois-exp    { background:rgba(251,191,36,.14); color:#fcd34d; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .whois-expd   { background:rgba(244,63,94,.16); color:#fda4af; border-radius:6px; padding:2px 8px; font-size:11px; font-weight:700; }
  .whois-unk    { color:var(--faint); font-size:11px; }

  .no-results { padding:48px; text-align:center; color:var(--muted); font-size:15px; }

  .pagination { display:flex; align-items:center; gap:6px; margin-top:14px; justify-content:flex-end; flex-wrap:wrap; }
  .pg-btn { background:var(--surface); border:1px solid var(--border); color:var(--text);
            padding:6px 11px; border-radius:var(--radius-sm); cursor:pointer; font-size:12px; }
  .pg-btn:hover { border-color:var(--accent); color:var(--accent); }
  .pg-btn.active { background:var(--accent); color:#04121f; border-color:var(--accent); font-weight:700; }
  .pg-btn:disabled { opacity:.4; cursor:default; }
  .pg-info { color:var(--muted); font-size:12px; margin-right:auto; }

  /* ── Rodapé ──────────────────────────────────────────── */
  .footer { margin-top:30px; padding-top:18px; border-top:1px solid var(--border); color:var(--faint);
            font-size:11.5px; display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; }
  .footer a { color:var(--muted); text-decoration:none; }

  /* ── Portal (hub / dashboard / guia) ─────────────────── */
  .hero { margin:8px 0 24px; }
  .hero h1 { font-size:30px; font-weight:800; letter-spacing:-.4px; }
  .hero-tag { color:var(--accent); font-size:14px; font-weight:600; margin-top:3px; }
  .hero p { color:var(--muted); margin-top:9px; max-width:700px; font-size:14px; line-height:1.6; }
  /* Hero estilo "poster" (identidade visual) */
  .hero-center { text-align:center; margin:26px 0 30px; }
  .hero-center .logo-xl .logo { width:94px; height:94px; filter:drop-shadow(0 0 26px rgba(51,163,239,.38)); }
  .wordmark { font-size:48px; font-weight:800; letter-spacing:9px; margin:12px 0 0; line-height:1;
              background:linear-gradient(180deg,#eef5fd 34%,#9db2cd); -webkit-background-clip:text;
              background-clip:text; color:transparent; }
  .hero-center .hero-tag { color:var(--accent); letter-spacing:4.5px; text-transform:uppercase;
              font-size:12px; font-weight:700; margin-top:6px; }
  .slogan { color:var(--muted); font-size:15px; margin-top:13px; }
  .slogan b { color:var(--text); font-weight:700; }
  .pillars { display:flex; justify-content:center; flex-wrap:wrap; margin:22px auto 0; max-width:700px; }
  .pillar { display:flex; flex-direction:column; align-items:center; gap:9px; padding:6px 30px; position:relative; }
  .pillar + .pillar::before { content:''; position:absolute; left:0; top:12%; height:76%; width:1px; background:var(--border); }
  .pillar svg { width:30px; height:30px; color:var(--accent); }
  .pillar span { font-size:11px; letter-spacing:2px; text-transform:uppercase; font-weight:600; color:var(--muted); }
  .hero-desc { color:var(--muted); max-width:700px; margin:20px auto 4px; font-size:13.5px; line-height:1.6; text-align:center; }
  .hub-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:14px; }
  .hub-card { display:flex; gap:14px; align-items:flex-start; padding:18px; text-decoration:none; color:inherit;
              background:linear-gradient(180deg,var(--surface),var(--surface-2)); border:1px solid var(--border);
              border-radius:var(--radius); box-shadow:var(--shadow); transition:.15s; }
  .hub-card:hover { border-color:var(--accent); transform:translateY(-2px); }
  .hub-card .ic { width:42px; height:42px; flex:none; border-radius:11px; display:grid; place-items:center;
                  background:rgba(51,163,239,.12); color:var(--accent); }
  .hub-card .ic svg { width:22px; height:22px; }
  .hub-card h3 { font-size:15px; font-weight:700; }
  .hub-card p { color:var(--muted); font-size:12.5px; margin-top:5px; line-height:1.5; }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  @media (max-width:860px){ .grid-2 { grid-template-columns:1fr; } }
  /* Resumo executivo (topo dos relatórios) */
  .exec { padding:18px 20px; margin-bottom:20px; border-left:3px solid var(--accent); }
  .exec h2 { font-size:14px; color:var(--accent); text-transform:uppercase; letter-spacing:.7px;
             margin-bottom:10px; display:flex; align-items:center; gap:8px; }
  .exec-lead { color:#cbd5e1; font-size:13.5px; line-height:1.6; margin-bottom:14px; }
  .exec-lead b { color:var(--red); }
  .exec-grid { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
  @media (max-width:820px){ .exec-grid { grid-template-columns:1fr; } }
  .exec-grid h3 { font-size:11.5px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; margin-bottom:9px; }
  .exec-risks, .exec-recs { list-style:none; display:flex; flex-direction:column; gap:7px; }
  .exec-risks li { font-size:12.5px; color:var(--text); }
  .exec-risks .sv { font-weight:800; margin-right:7px; font-size:11px; }
  .exec-recs li { font-size:12.5px; color:#cbd5e1; line-height:1.5; padding-left:18px; position:relative; }
  .exec-recs li::before { content:'\\2192'; position:absolute; left:0; color:var(--accent); font-weight:700; }
  .exec-none { color:var(--green); font-size:13px; }

  /* Accordion (recolhe seções secundárias p/ reduzir densidade) */
  .acc > summary { cursor:pointer; list-style:none; display:flex; align-items:center; gap:8px;
       font-size:12.5px; color:var(--accent); text-transform:uppercase; letter-spacing:.7px; font-weight:700; }
  .acc > summary::-webkit-details-marker { display:none; }
  .acc > summary::after { content:'\\25BE'; margin-left:auto; color:var(--muted); transition:transform .15s; }
  .acc[open] > summary::after { transform:rotate(180deg); }
  .acc[open] > summary { margin-bottom:12px; }
  .panel-pad { padding:18px 20px; }
  .panel-pad h2 { font-size:14px; color:var(--accent); text-transform:uppercase; letter-spacing:.7px;
                  margin-bottom:14px; display:flex; align-items:center; gap:8px; }
  .panel-pad h2 .badge { margin-left:auto; }
  .list-row { display:flex; align-items:flex-start; gap:12px; padding:11px 0; border-bottom:1px solid var(--border); }
  .list-row:last-child { border-bottom:none; }
  .list-row .ic2 { color:var(--muted); margin-top:1px; font-size:15px; }
  .list-row .nm { font-weight:600; font-size:13px; }
  .list-row .dt { font-size:11.5px; color:var(--muted); margin-top:3px; line-height:1.6; }
  .empty { color:var(--muted); font-size:12.5px; font-style:italic; padding:6px 0; }
  .pill-ok { background:rgba(52,211,153,.14); color:#6ee7b7; border-radius:999px; padding:2px 10px; font-size:11px; font-weight:700; }
  .flow { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin:14px 0; padding:14px;
          background:var(--bg); border:1px solid var(--border); border-radius:var(--radius); font-size:12px; }
  .flow-step { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:8px 14px; text-align:center; min-width:120px; }
  .flow-step .l { font-size:11px; color:var(--muted); margin-bottom:2px; text-transform:uppercase; letter-spacing:.4px; }
  .flow-step .v { font-weight:700; color:var(--text); }
  .flow-step.res { background:rgba(51,163,239,.10); border-color:rgba(51,163,239,.3); }
  .flow-step.res .v { color:var(--accent); }
  .flow-arrow { color:var(--faint); font-size:16px; }
  .risk-table { width:100%; border-collapse:separate; border-spacing:0; font-size:13px; margin-top:6px; }
  .risk-table th { background:#0e1727; color:var(--muted); padding:9px 12px; text-align:left; font-size:11px;
                   text-transform:uppercase; letter-spacing:.5px; border-bottom:1px solid var(--border-2); position:static; cursor:default; }
  .risk-table td { padding:9px 12px; border-bottom:1px solid rgba(35,49,76,.6); vertical-align:top; }
  .risk-table td, .risk-table th { white-space:normal; word-break:break-word; overflow-wrap:anywhere; }
  .risk-table.rt-fixed { table-layout:fixed; }
  .risk-table.rt-fixed td, .risk-table.rt-fixed th { word-break:normal; }
  .risk-table tr:hover td { background:transparent; }
  .r-critico{color:var(--red);font-weight:700} .r-alto{color:var(--orange);font-weight:700}
  .r-medio{color:var(--yellow);font-weight:600} .r-baixo{color:var(--green)}
  .b-crit{background:rgba(244,63,94,.16);color:#fda4af;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700}
  .b-alto{background:rgba(251,146,60,.16);color:#fdba74;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700}
  .b-med{background:rgba(251,191,36,.14);color:#fcd34d;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700}
  .b-bai{background:rgba(52,211,153,.14);color:#6ee7b7;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:700}
  .sect p { color:#cbd5e1; font-size:13px; line-height:1.7; margin-bottom:10px; }
  .sbar { display:flex; height:10px; border-radius:6px; overflow:hidden; margin:10px 0 4px; }
  .sbar i { flex:1; display:block; }

  /* ── Botão de tema (dark/light) ──────────────────────── */
  .theme-toggle { flex:none; width:34px; height:34px; display:inline-flex; align-items:center; justify-content:center;
       border:1px solid var(--border); background:var(--surface); color:var(--muted); border-radius:var(--radius-sm);
       cursor:pointer; transition:.15s; }
  .theme-toggle:hover { color:var(--accent); border-color:var(--accent); }
  .theme-toggle svg { width:16px; height:16px; }
  .theme-toggle .ic-sun { display:none; }
  body.light .theme-toggle .ic-moon { display:none; }
  body.light .theme-toggle .ic-sun { display:inline; }

  /* ── Tema claro (suave, sem ofuscar a vista) ─────────── */
  body.light {
    --bg:#dfe6f0; --bg-grad:radial-gradient(1150px 580px at 78% -12%, #eef3fa 0%, #dfe6f0 60%);
    --surface:#f4f7fb; --surface-2:#e9eef6; --border:#c3cfe0; --border-2:#a8b7cd;
    --text:#16243d; --muted:#3e4d64; --faint:#67768f; --accent:#1769c0; --accent-2:#5b62e0;
    --steel:#3a4f6e; --steel-2:#3d4d68;
    --red:#dc2626; --orange:#d9620a; --yellow:#b45309; --green:#0f9d6b; --pink:#db2777;
    --shadow:0 10px 28px -18px rgba(20,40,80,.35);
  }
  body.light .topbar { background:rgba(244,247,251,.86); }
  body.light th { background:#e6ecf5; }
  body.light .risk-table th { background:#e6ecf5; }
  body.light td { border-bottom-color:rgba(120,140,170,.32); }
  body.light .risk-table td { border-bottom-color:rgba(120,140,170,.32); }
  body.light tbody tr:nth-child(even) td { background:rgba(20,40,80,.022); }
  body.light td code, body.light code { color:#0b5cab; }
  body.light .wordmark { background:linear-gradient(180deg,#2b3e5b 34%,#5b708f);
       -webkit-background-clip:text; background-clip:text; color:transparent; }
  body.light .sect p, body.light .exec-lead, body.light .exec-recs li { color:#41506a; }
  body.light .pg-btn.active { color:#fff; }
  /* pílulas: texto mais escuro para contraste no claro */
  body.light .cve-badge, body.light .dnssec-off, body.light .ssl-bad,
  body.light .whois-novo, body.light .whois-expd, body.light .b-crit { color:#be123c; }
  body.light .ip-PRIVADO, body.light .dnssec-on, body.light .ssl-ok,
  body.light .whois-estab, body.light .pill-ok, body.light .b-bai { color:#047857; }
  body.light .ssl-warn, body.light .whois-recente, body.light .whois-exp, body.light .b-med { color:#a15c07; }
  body.light .b-alto { color:#c2570a; }
  body.light .ip-PUBLICO, body.light .origem-crtsh, body.light .us-link { color:#0369a1; }
  body.light .actions select { color:#0b5e96; }
  body.light .camp-badge, body.light .tor-badge { color:#4338ca; }
  body.light .origem-urlscan, body.light .us-seen { color:#7e22ce; }
  body.light .status-RECONHECIDO { color:#6d28d9; }

  /* ── Responsivo: navegação colapsável (mobile/tablet) ──── */
  @media (max-width:820px) {
    .nav-toggle { display:inline-flex; margin-left:auto; }
    .nav { display:none; position:absolute; top:100%; left:0; right:0; flex-direction:column; gap:2px;
           background:rgba(8,12,22,.98); backdrop-filter:blur(10px); border-bottom:1px solid var(--border);
           padding:8px; z-index:30; max-height:calc(100vh - 58px); overflow:auto; }
    .nav.open { display:flex; }
    .nav a { min-height:44px; padding:12px 14px; font-size:14px; }
    body.light .nav { background:rgba(244,247,251,.98); }
    .topbar { gap:10px; padding:0 16px; }
    /* Mobile: esconde o subtítulo do brand p/ a topbar caber em 360px (evita scroll horizontal). */
    .brand { min-width:0; }
    .brand .sub { display:none; }
    .wrap { padding:18px 16px 48px; }
    .breadcrumb { padding:9px 16px 0; }
    .summary { grid-template-columns:1fr; }
    .page-head { flex-direction:column; align-items:flex-start; }
  }

  @media print {
    body { background:#fff !important; color:#000 !important; font-size:11px; }
    .wrap { padding:8px; max-width:none; }
    .topbar,.toolbar,.tabs,.pagination,.btn,.actions,.no-print { display:none !important; }
    .panel,.kpi,.tbl-wrap { box-shadow:none !important; }
    th { background:#eee !important; color:#000 !important; position:static; }
    td { border:1px solid #bbb !important; }
    .risk-CRITICO { color:#c00 !important; } .risk-ALTO { color:#c60 !important; }
    .score-critical,.whois-novo { animation:none !important; }
    .summary { grid-template-columns:1fr 1fr !important; }
  }
"""


# ============================================================
# COMPONENTES HTML COMPARTILHADOS (identidade ASM)
# ============================================================

def _logo_svg(size: int = 32) -> str:
    """Logo Argus — olho-radar (eye-radar): anel de mira (crosshair) prata +
    pálpebra em amêndoa + íris azul com reticulado e glint. SVG inline, escalável,
    offline. Inspirado na identidade visual oficial (prata/azul sobre navy)."""
    return (
        f'<svg class="logo" width="{size}" height="{size}" viewBox="0 0 32 32" fill="none" '
        'xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
        '<defs>'
        '<linearGradient id="lg-steel" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#eaf2fb"/><stop offset="1" stop-color="#9db2cd"/></linearGradient>'
        '<linearGradient id="lg-blue" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#5cc2ff"/><stop offset="1" stop-color="#2b85db"/></linearGradient>'
        '<radialGradient id="lg-iris" cx="0.4" cy="0.35" r="0.78">'
        '<stop offset="0" stop-color="#d6ecff"/><stop offset="0.45" stop-color="#2f93de"/>'
        '<stop offset="1" stop-color="#0e4d8a"/></radialGradient>'
        '</defs>'
        # anel de mira (radar) + ticks cardeais
        '<circle cx="16" cy="16" r="13.4" stroke="url(#lg-steel)" stroke-width="1.2" opacity="0.85"/>'
        '<g stroke="url(#lg-steel)" stroke-width="1.6" stroke-linecap="round">'
        '<path d="M16 1.4V5"/><path d="M16 27V30.6"/><path d="M1.4 16H5"/><path d="M27 16H30.6"/></g>'
        # pálpebra (amêndoa): arco superior azul + inferior prata
        '<path d="M3.6 16 Q16 6 28.4 16" stroke="url(#lg-blue)" stroke-width="1.9" stroke-linecap="round"/>'
        '<path d="M3.6 16 Q16 25.6 28.4 16" stroke="url(#lg-steel)" stroke-width="1.5" stroke-linecap="round" opacity="0.9"/>'
        # íris azul + reticulado tech
        '<circle cx="16" cy="16" r="6.1" fill="url(#lg-iris)"/>'
        '<circle cx="16" cy="16" r="6.1" stroke="#bfe4ff" stroke-width="0.5" opacity="0.45"/>'
        '<circle cx="16" cy="16" r="4.0" stroke="#cfe9ff" stroke-width="0.5" opacity="0.5"/>'
        '<g stroke="#dbefff" stroke-width="0.4" opacity="0.4"><path d="M16 10.6v10.8"/><path d="M10.6 16h10.8"/></g>'
        # pupila + brilho (glint)
        '<circle cx="16" cy="16" r="2.3" fill="#06223f"/>'
        '<circle cx="18" cy="13.5" r="1.05" fill="#ffffff" opacity="0.92"/>'
        '</svg>'
    )


# Favicon SVG (olho-radar — mira + íris azul) embutido como data URI, sem arquivo externo.
_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
    "<defs><radialGradient id='i' cx='0.4' cy='0.35' r='0.78'>"
    "<stop offset='0' stop-color='#d6ecff'/><stop offset='0.5' stop-color='#2f93de'/>"
    "<stop offset='1' stop-color='#0e4d8a'/></radialGradient></defs>"
    "<rect width='32' height='32' rx='7' fill='#070c16'/>"
    "<circle cx='16' cy='16' r='12.4' fill='none' stroke='#aebfd6' stroke-width='1.1' opacity='0.8'/>"
    "<g stroke='#aebfd6' stroke-width='1.5' stroke-linecap='round'>"
    "<path d='M16 2.6V5.4'/><path d='M16 26.6V29.4'/><path d='M2.6 16H5.4'/><path d='M26.6 16H29.4'/></g>"
    "<path d='M5 16 Q16 7.6 27 16' fill='none' stroke='#4fb0f5' stroke-width='1.7' stroke-linecap='round'/>"
    "<path d='M5 16 Q16 24.4 27 16' fill='none' stroke='#aebfd6' stroke-width='1.3' stroke-linecap='round' opacity='0.85'/>"
    "<circle cx='16' cy='16' r='5.3' fill='url(#i)'/>"
    "<circle cx='16' cy='16' r='1.9' fill='#06223f'/>"
    "<circle cx='17.7' cy='13.9' r='0.9' fill='#ffffff' opacity='0.9'/></svg>"
)
_FAVICON = "data:image/svg+xml;base64," + base64.b64encode(_FAVICON_SVG.encode("utf-8")).decode("ascii")


_NAV_ICONS = {
    # Dashboard — grade de painéis
    "dashboard":  '<svg viewBox="0 0 16 16" fill="currentColor"><rect x="1.5" y="1.5" width="5.3" height="6.6" rx="1.2"/>'
                  '<rect x="1.5" y="9.6" width="5.3" height="4.9" rx="1.2"/><rect x="9.2" y="1.5" width="5.3" height="4.4" rx="1.2"/>'
                  '<rect x="9.2" y="7.4" width="5.3" height="7.1" rx="1.2"/></svg>',
    # Portas — pilha de servidores com LED (hosts/serviços)
    "monitor":    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3">'
                  '<rect x="2" y="2.4" width="12" height="4.3" rx="1.2"/><rect x="2" y="9.3" width="12" height="4.3" rx="1.2"/>'
                  '<circle cx="4.6" cy="4.55" r=".75" fill="currentColor" stroke="none"/>'
                  '<circle cx="4.6" cy="11.45" r=".75" fill="currentColor" stroke="none"/>'
                  '<path d="M7 4.55h4.6M7 11.45h4.6" stroke-linecap="round"/></svg>',
    # Subdomínios — sitemap (domínio raiz ramificando em subdomínios)
    "submonitor": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.25">'
                  '<rect x="5.8" y="1.4" width="4.4" height="3.2" rx="1"/><rect x="1.3" y="11" width="4" height="3.2" rx="1"/>'
                  '<rect x="6" y="11" width="4" height="3.2" rx="1"/><rect x="10.7" y="11" width="4" height="3.2" rx="1"/>'
                  '<path d="M8 4.6v3M3.3 11V7.6h9.4V11M8 7.6V11" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    # Credenciais — chave
    "credentials":'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3">'
                  '<circle cx="5.3" cy="5.3" r="3.4"/><path d="M7.7 7.7 13.2 13.2M11.2 11.2l1.4-1.4M13 13l1.4-1.4" stroke-linecap="round"/></svg>',
    # E-mail — envelope (postura SPF/DMARC/DKIM)
    "email":      '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3">'
                  '<rect x="1.6" y="3" width="12.8" height="10" rx="1.7"/>'
                  '<path d="M2.3 4.2 8 8.7 13.7 4.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    # Gestão de Achados — prancheta com check (triagem/tratamento)
    "findings":   '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.25">'
                  '<rect x="3" y="2.4" width="10" height="12.2" rx="1.6"/>'
                  '<rect x="5.6" y="1.3" width="4.8" height="2.4" rx="0.8"/>'
                  '<path d="M5.6 8.2 7.1 9.7 10.4 6.3" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    # Typosquat — domínios sósia (clone/duplicado)
    "typosquat":  '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3">'
                  '<rect x="1.9" y="1.9" width="8" height="8" rx="1.5"/>'
                  '<rect x="6.1" y="6.1" width="8" height="8" rx="1.5"/></svg>',
    # Guia de Risco — escudo com alerta
    "risk":       '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3">'
                  '<path d="M8 1.4 14 3.8v4.1c0 3.9-2.6 6-6 6.7-3.4-.7-6-2.8-6-6.7V3.8z" stroke-linejoin="round"/>'
                  '<path d="M8 5.2v3.1" stroke-linecap="round"/><circle cx="8" cy="10.6" r=".5" fill="currentColor" stroke="none"/></svg>',
    # Correlação — grafo: nós ligados (domínio/subdomínio/IP compartilhado)
    "correlacao": '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3">'
                  '<circle cx="3.2" cy="8" r="1.8"/><circle cx="12.8" cy="3.4" r="1.8"/>'
                  '<circle cx="12.8" cy="12.6" r="1.8"/>'
                  '<path d="M4.8 7.1 11.2 4.1M4.8 8.9l6.4 3" stroke-linecap="round"/></svg>',
}


# Pilares do produto (faixa do hero) — espelham a identidade visual: Discover ·
# Enumerate · Assess · Prioritize.
_PILLAR_ICONS = {
    "discover":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">'
                  '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/>'
                  '<circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/>'
                  '<path d="M12 12 18.5 7" stroke-linecap="round"/></svg>',
    "enumerate":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">'
                  '<circle cx="12" cy="12" r="9"/><path d="M3 12h18" stroke-linecap="round"/>'
                  '<path d="M12 3c3.2 2.8 3.2 15.2 0 18M12 3c-3.2 2.8-3.2 15.2 0 18" stroke-linecap="round"/></svg>',
    "assess":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">'
                  '<path d="M12 2 20 5v6c0 5-3.4 8-8 9.5C7.4 19 4 16 4 11V5z" stroke-linejoin="round"/>'
                  '<path d="M8.6 11.7 11 14.1l4.3-4.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    "prioritize": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round">'
                  '<path d="M5 20v-5M12 20V9M19 20V4"/></svg>',
}


def _topbar(active: str) -> str:
    """Barra de navegação persistente (identidade do produto)."""
    items = [
        ("dashboard",   "/dashboard.html",          "Dashboard"),
        ("findings",    "/findings_report.html",    "Gestão de Achados"),
        ("monitor",     "/monitor_report.html",     "Portas"),
        ("submonitor",  "/submonitor_report.html",  "Subdomínios"),
        ("correlacao",  "/correlacao.html",         "Correlação"),
        ("credentials", "/credentials_report.html", "Credenciais"),
        ("email",       "/email_report.html",       "E-mail"),
        ("typosquat",   "/typosquat_report.html",   "Typosquat"),
        ("risk",        "/risk-guide.html",         "Guia de Risco"),
    ]
    links = "".join(
        f'<a class="{"active" if key==active else ""}" href="{href}"'
        f'{" aria-current=\"page\"" if key==active else ""}>'
        f'{_NAV_ICONS.get(key,"").replace("<svg", "<svg aria-hidden=\"true\"", 1)}{label}</a>'
        for key, href, label in items
    )
    # Breadcrumb: Início › <seção atual> — orientação secundária de localização.
    _cur_label = next((label for key, _href, label in items if key == active), "")
    breadcrumb = (
        '<div class="breadcrumb"><a href="/index.html">Início</a>'
        + (f'<span class="sep">&rsaquo;</span><span class="cur">{_cur_label}</span>' if _cur_label else "")
        + '</div>'
    ) if _cur_label else ""
    return (
        '<a class="skip-link" href="#conteudo">Pular para o conteúdo</a>'
        '<div id="navprog"></div>'
        '<script>'
        "(function(){try{if(localStorage.getItem('argus-theme')==='light')document.body.classList.add('light');}catch(e){}})();"
        "function argusToggleTheme(){var l=document.body.classList.toggle('light');"
        "try{localStorage.setItem('argus-theme',l?'light':'dark');}catch(e){}}"
        "function argusToggleNav(){var n=document.querySelector('.nav');if(!n)return;"
        "var o=n.classList.toggle('open');var b=document.querySelector('.nav-toggle');"
        "if(b)b.setAttribute('aria-expanded',o?'true':'false');}"
        # Feedback de carregamento: ao navegar para outra página, anima a barra do topo.
        "(function(){var b=document.getElementById('navprog');if(!b)return;function go(){b.classList.add('go');}"
        "window.addEventListener('beforeunload',go);"
        "document.addEventListener('click',function(e){var a=e.target.closest&&e.target.closest('a[href]');if(!a)return;"
        "var h=a.getAttribute('href')||'';if(a.target==='_blank'||a.hasAttribute('download'))return;"
        "if(h.charAt(0)==='#'||h.indexOf('javascript:')===0||h.indexOf('mailto:')===0)return;"
        "if(a.origin&&a.origin!==location.origin)return;go();},true);"
        "window.addEventListener('pageshow',function(){b.classList.remove('go');});})();"
        '</script>'
        '<div class="topbar">'
        f'<a class="brand" href="/index.html" title="Início" aria-label="Argus — Início">{_logo_svg()}<span class="bwrap"><span class="bn">ARGUS</span>'
        f'<span class="sub">Attack Surface Management</span></span></a>'
        f'<nav class="nav">{links}</nav>'
        '<button class="nav-toggle" type="button" onclick="argusToggleNav()"'
        ' aria-label="Abrir menu de navegação" aria-expanded="false">'
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">'
        '<line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>'
        '</button>'
        '<button class="theme-toggle" type="button" onclick="argusToggleTheme()"'
        ' title="Tema claro/escuro" aria-label="Alternar tema claro ou escuro">'
        '<svg class="ic-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
        ' stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'
        '<svg class="ic-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
        ' stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/>'
        '<path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41'
        'M19.07 4.93l-1.41 1.41M6.34 17.66l-1.41 1.41"/></svg>'
        '</button>'
        '<a class="theme-toggle" href="/logout" title="Sair" aria-label="Sair"'
        ' style="margin-left:6px;text-decoration:none">'
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>'
        '<polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>'
        '</a>'
        '</div>'
        + breadcrumb
    )


def _footer() -> str:
    year = datetime.datetime.now().year
    return (
        '<div class="footer">'
        '<span>Argus — plataforma de monitoramento de superfície de ataque</span>'
        f'<span>Gerado automaticamente pelo Argus · &copy; {year}</span>'
        '</div>'
    )


# Segmentos de severidade (rótulo, classe-cor, cor hex) para o donut e legenda
_SEV_SEGMENTS = [
    ("CRITICO", "var(--red)",    "#f43f5e"),
    ("ALTO",    "var(--orange)", "#fb923c"),
    ("MEDIO",   "var(--yellow)", "#fbbf24"),
    ("BAIXO",   "var(--green)",  "#34d399"),
    ("INFO",    "var(--muted)",  "#8a99b4"),
]


def _donut(counts: dict, title: str = "Distribuição de Risco") -> str:
    """Donut SVG (sem JS/lib) a partir de um dict {SEVERIDADE: contagem}."""
    segs = [(lbl, color, int(counts.get(lbl, 0))) for lbl, _cssvar, color in _SEV_SEGMENTS]
    total = sum(v for _l, _c, v in segs)
    r, cx, cy = 52, 60, 60
    circ = 2 * 3.141592653589793 * r
    offset = 0.0
    arcs = ""
    if total > 0:
        for _lbl, color, val in segs:
            if val <= 0:
                continue
            frac = val / total
            dash = frac * circ
            arcs += (
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="14" '
                f'stroke-dasharray="{dash:.2f} {circ - dash:.2f}" stroke-dashoffset="{-offset:.2f}" '
                f'transform="rotate(-90 {cx} {cy})"/>'
            )
            offset += dash
    else:
        arcs = f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="var(--border)" stroke-width="14"/>'

    legend = ""
    for _lbl, color, val in segs:
        if total == 0 and val == 0 and _lbl in ("INFO",):
            pass
        legend += (
            f'<div class="legend-item"><span class="dot" style="background:{color}"></span>'
            f'{_lbl.capitalize()}<b>{val}</b></div>'
        )

    return (
        '<div class="panel donut-card"><h2>' + title + '</h2><div class="donut-flex">'
        f'<svg class="donut" viewBox="0 0 120 120">{arcs}'
        f'<text class="tot" x="60" y="60" text-anchor="middle" dominant-baseline="central">{total}</text>'
        '<text class="totl" x="60" y="78" text-anchor="middle">ATIVOS</text></svg>'
        f'<div class="legend">{legend}</div></div></div>'
    )


def _kpi_tiles(tiles: list) -> str:
    """tiles: lista de (valor, rótulo, classe_sev[, id_opcional]). O 4º item
    (opcional) é o id do número, p/ atualização via JS. Retorna a grade de KPIs."""
    cells = ""
    for t in tiles:
        val, lbl, cls = t[0], t[1], t[2]
        vid = t[3] if len(t) > 3 else ""
        idattr = f' id="{vid}"' if vid else ""
        cells += f'<div class="kpi {cls}"><div class="v"{idattr}>{val}</div><div class="l">{lbl}</div></div>'
    return f'<div class="kpi-grid">{cells}</div>'


# ============================================================
# RESUMO EXECUTIVO (gerado dos dados — útil p/ gestão)
# ============================================================

_SEV_RANK = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}

def _h(v) -> str:
    """HTML-escape seguro de valores dinâmicos (banner/serviço podem conter HTML)."""
    return html.escape("" if v is None else str(v))


def _exec_panel(lead: str, risks: list, recs: list) -> str:
    risks_html = "".join(f"<li>{r}</li>" for r in risks) or \
        '<li class="exec-none">Nenhuma exposição crítica ou de alto risco.</li>'
    recs_html = "".join(f"<li>{r}</li>" for r in recs) or \
        '<li class="exec-none">Sem recomendações prioritárias.</li>'
    return (
        '<div class="panel exec">'
        '<h2>&#x1F4CB; Resumo Executivo</h2>'
        f'<p class="exec-lead">{lead}</p>'
        '<div class="exec-grid">'
        f'<div><h3>Principais riscos</h3><ol class="exec-risks">{risks_html}</ol></div>'
        f'<div><h3>Recomendações</h3><ul class="exec-recs">{recs_html}</ul></div>'
        '</div></div>'
    )


def _top_risks(rows: list, fmt) -> list:
    """Top 5 findings atuais por severidade (exclui MEDIO/BAIXO/INFO)."""
    cur = [r for r in rows if r.get("risk") in ("CRITICO", "ALTO", "MEDIO")]
    cur.sort(key=lambda r: _SEV_RANK.get(r.get("risk"), 5))
    out = []
    for r in cur[:5]:
        sv = r.get("risk")
        out.append(f'<span class="sv risk-{sv}">{sv}</span> {fmt(r)}')
    return out


def _exec_monitor(all_results: list) -> str:
    cur   = [r for r in all_results if r.get("status") in ("NOVO", "REINCIDENTE")]
    ncamp = len({r.get("campanha") for r in cur if r.get("campanha")})
    nips  = len({r.get("ip") for r in cur if r.get("ip")})
    tc    = sum(1 for r in cur if r.get("risk") == "CRITICO")
    ta    = sum(1 for r in cur if r.get("risk") == "ALTO")
    lead  = (f"{len(cur)} porta(s) aberta(s) em {nips} IP(s), {ncamp} campanha(s). " +
             (f"<b>{tc} crítica(s)</b> e {ta} de alto risco exigem atenção imediata."
              if (tc or ta) else "Nenhuma exposição crítica ou de alto risco nesta execução."))
    risks = _top_risks(cur, lambda r: f'{_h(r.get("port"))}/{_h(r.get("service") or "?")} '
                                      f'em {_h(r.get("ip"))} ({_h(r.get("ip_type"))})')
    ports = {int(r.get("port") or 0) for r in cur}
    recs = []
    def add(c):
        if c not in recs: recs.append(c)
    if tc: add("Há portas críticas expostas — restrinja por firewall/VPN e remova serviços sensíveis do acesso público.")
    if ports & {3389, 5900, 5985, 5986}: add("Acesso remoto (RDP/VNC/WinRM) exposto — proteja com VPN e MFA.")
    if ports & {3306, 5432, 1433, 27017, 6379, 9200, 9300, 5984, 1521}: add("Banco de dados acessível externamente — restrinja a redes internas.")
    if ports & {23, 21, 69, 512, 513, 514, 111, 2049, 161}: add("Protocolos inseguros/legados expostos — desabilite e use alternativas cifradas.")
    if ports & {445, 139, 137, 138, 135}: add("SMB/NetBIOS/RPC exposto (vetor de ransomware) — bloqueie no perímetro.")
    if ports & {2375, 4243, 2379, 2380, 6443, 8500, 8200, 5601, 9090, 3000}: add("Painéis/orquestração (Docker/K8s/Grafana/…) expostos — restrinja o acesso.")
    if any(((r.get("abuse") or {}).get("abuse_confidence_score") or 0) >= 50 for r in cur):
        add("IPs com má reputação (AbuseIPDB ≥ 50) — investigue e considere bloqueio.")
    return _exec_panel(lead, risks, recs)


def _exec_submonitor(all_results: list) -> str:
    cur   = [r for r in all_results if r.get("status") in ("NOVO", "REINCIDENTE")]
    ncamp = len({r.get("campanha") for r in cur if r.get("campanha")})
    tc    = sum(1 for r in cur if r.get("risk") == "CRITICO")
    ta    = sum(1 for r in cur if r.get("risk") == "ALTO")
    lead  = (f"{len(cur)} subdomínio(s) ativo(s) em {ncamp} campanha(s). " +
             (f"<b>{tc} crítico(s)</b> e {ta} de alto risco exigem atenção."
              if (tc or ta) else "Nenhuma exposição crítica ou de alto risco nesta execução."))
    def fmt(r):
        ip = r.get("ip", "")
        return f'{_h(r.get("hostname"))}' + (f' ({_h(ip)})' if ip else '')
    risks = _top_risks(cur, fmt)
    recs = []
    def add(c):
        if c not in recs: recs.append(c)
    if any(r.get("risk") == "CRITICO" for r in cur): add("Subdomínios críticos — IPs com CVE explorada in-the-wild (KEV), CVSS alto ou reputação péssima. Priorize a correção/retirada.")
    if any(r.get("risk") == "ALTO" for r in cur): add("Subdomínios de alto risco — IPs com vulnerabilidade conhecida ou reputação ruim. Valide e trate.")
    if any((r.get("whois") or {}).get("status") == "NOVO" for r in cur): add("Domínios recém-registrados detectados — verifique legitimidade (possível phishing/typosquatting).")
    if any((r.get("ssl") or {}).get("status", "").startswith("EXPIRA") for r in cur): add("Certificados TLS vencidos ou próximos do vencimento — renove.")
    if any((r.get("urlscan") or {}).get("seen") for r in cur): add("Subdomínios aparecem em scans públicos (urlscan) — revise a exposição.")
    return _exec_panel(lead, risks, recs)


def _exec_credentials(all_results: list) -> str:
    cur = [r for r in all_results if r.get("status") in ("NOVO", "REINCIDENTE") and int(r.get("total") or 0) > 0]
    comp = len(cur)
    emp  = sum(int(r.get("employees") or 0) for r in cur)
    usr  = sum(int(r.get("users") or 0) for r in cur)
    lead = (f"{comp} domínio(s) com exposição em logs de infostealer "
            f"(<b>{emp} funcionário(s)</b> e {usr} usuário(s) comprometido(s))."
            if comp else "Nenhuma exposição de credenciais identificada nesta execução.")
    cur.sort(key=lambda r: (_SEV_RANK.get(r.get("risk"), 5), -int(r.get("total") or 0)))
    risks = []
    for r in cur[:5]:
        sv = r.get("risk")
        det = (f'{r.get("employees")} funcionário(s)' if int(r.get("employees") or 0) > 0
               else f'{r.get("users")} usuário(s)')
        risks.append(f'<span class="sv risk-{sv}">{sv}</span> {_h(r.get("domain"))} — {_h(det)} comprometido(s)')
    recs = []
    def add(c):
        if c not in recs: recs.append(c)
    if emp: add("Credenciais de funcionários em logs de infostealer — force reset de senha + MFA e investigue as máquinas comprometidas.")
    if usr: add("Credenciais de clientes/usuários vazadas — force reset e monitore account takeover (ATO).")
    if any((r.get("clients_urls") or r.get("employees_urls")) for r in cur): add("Aplicações de login aparecem em stealer logs — reforce MFA e detecção de ATO nessas apps.")
    return _exec_panel(lead, risks, recs)


def _exec_email(all_results: list) -> str:
    cur   = [r for r in all_results if r.get("status") in ("NOVO", "REINCIDENTE")]
    ncamp = len({r.get("campanha") for r in cur if r.get("campanha")})
    tc    = sum(1 for r in cur if r.get("risk") == "CRITICO")
    ta    = sum(1 for r in cur if r.get("risk") == "ALTO")
    spoofable = tc + ta
    lead  = (f"{len(cur)} domínio(s) avaliado(s) em {ncamp} campanha(s). " +
             (f"<b>{spoofable} domínio(s) spoofável(is)</b> (sem SPF/DMARC eficaz) — "
              f"vetor direto de phishing e fraude (BEC)."
              if spoofable else "Nenhum domínio com postura de e-mail crítica nesta execução."))
    cur_sorted = sorted(cur, key=lambda r: _SEV_RANK.get(r.get("risk"), 5))
    risks = []
    for r in cur_sorted[:5]:
        sv = r.get("risk")
        if sv not in ("CRITICO", "ALTO", "MEDIO"):
            continue
        prob = (r.get("issues") or ["postura fraca"])[0]
        risks.append(f'<span class="sv risk-{sv}">{sv}</span> {_h(r.get("domain"))} — {_h(prob)}')
    recs = []
    def add(c):
        if c not in recs: recs.append(c)
    if any((r.get("spf_status") == "AUSENTE") for r in cur):
        add("Domínios sem SPF — publique um registro <code>v=spf1 … -all</code> autorizando apenas os remetentes legítimos.")
    if any((r.get("dmarc_status") in ("AUSENTE", "NONE")) for r in cur):
        add("DMARC ausente ou em <code>p=none</code> — avance para <code>p=quarantine</code> e depois <code>p=reject</code> (com <code>rua</code> para relatórios).")
    if any((r.get("spf_status") in ("SOFTFAIL", "NEUTRO")) for r in cur):
        add("SPF em softfail/neutro (<code>~all</code>/<code>?all</code>) — endureça para <code>-all</code> após validar os remetentes.")
    if any((r.get("spf_status") in ("PERIGOSO", "INVALIDO")) for r in cur):
        add("SPF perigoso/inválido (<code>+all</code> ou múltiplos/permerror) — corrija para não autorizar qualquer remetente.")
    if any((r.get("dkim_status") == "NAO DETECTADO" and r.get("has_mx")) for r in cur):
        add("DKIM não detectado em domínios que recebem e-mail — confirme a assinatura DKIM dos provedores de envio.")
    return _exec_panel(lead, risks, recs)


# ============================================================
# JS UTILITÁRIOS COMPARTILHADOS
# ============================================================

def _common_js_utils() -> str:
    return r"""
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function scoreClass(s) {
  if(s<0) return 'score-na';
  if(s===0) return 'score-clean';
  if(s<=25) return 'score-low';
  if(s<=50) return 'score-medium';
  if(s<=75) return 'score-high';
  return 'score-critical';
}
function scoreLabel(s) {
  if(s<0) return 'N/A';
  if(s===0) return '0% Limpo';
  if(s<=25) return s+'% Baixo';
  if(s<=50) return s+'% Medio';
  if(s<=75) return s+'% Alto';
  return s+'% CRITICO';
}
function _sortVal(x,k) {
  if(k==='abuse_score')   return x.abuse?x.abuse.score:-1;
  if(k==='abuse_country') return x.abuse?x.abuse.country:'';
  if(k==='abuse_isp')     return x.abuse?x.abuse.isp:'';
  if(k==='abuse_reports') return x.abuse?x.abuse.total_reports:0;
  if(k==='abuse_last')    return x.abuse?x.abuse.last_reported_at:'';
  if(k==='urlscan_seen')  return (x.urlscan&&x.urlscan.seen)?1:0;
  if(k==='idb_vulns')     return x.internetdb?x.internetdb.vuln_count:0;
  return x[k]??'';
}
function renderPagination(pgDiv, page, pages, total, start, count, gotoFn) {
  if(pages<=1){pgDiv.innerHTML=`<span class="pg-info">Exibindo ${total} entrada(s)</span>`;return;}
  let h=`<span class="pg-info">Linhas ${start+1}&ndash;${start+count} de ${total}</span>`;
  h+=`<button class="pg-btn" onclick="${gotoFn}(${page-1})" ${page===1?'disabled':''}>&#x2039;</button>`;
  for(let p=1;p<=pages;p++){
    if(p===1||p===pages||(p>=page-2&&p<=page+2))
      h+=`<button class="pg-btn ${p===page?'active':''}" onclick="${gotoFn}(${p})">${p}</button>`;
    else if(p===page-3||p===page+3)
      h+=`<span style="color:var(--muted)">&#x2026;</span>`;
  }
  h+=`<button class="pg-btn" onclick="${gotoFn}(${page+1})" ${page===pages?'disabled':''}>&#x203A;</button>`;
  pgDiv.innerHTML=h;
}
// Download client-side (usado pelos exports Red Team / Threat Intel)
function dl(name, text, mime){
  const b=new Blob([text],{type:(mime||'text/plain')+';charset=utf-8;'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download=name; a.click();
}
function _today(){ return new Date().toISOString().slice(0,10); }
function uniq(arr){ return [...new Set(arr.filter(Boolean))]; }

// ── Badges de postura de e-mail (SPF/DMARC/DKIM/MX) ──
function spfBadge(s){
  if(s==='FORTE')    return '<span class="ssl-ok">SPF -all</span>';
  if(s==='SOFTFAIL') return '<span class="ssl-warn">SPF ~all</span>';
  if(s==='NEUTRO')   return '<span class="ssl-warn">SPF ?all</span>';
  if(s==='PERIGOSO') return '<span class="ssl-bad">SPF +all</span>';
  if(s==='INVALIDO') return '<span class="ssl-bad">SPF inválido</span>';
  if(s==='AUSENTE')  return '<span class="ssl-bad">sem SPF</span>';
  return '<span class="ssl-none">&#8212;</span>';
}
function dmarcBadge(s){
  if(s==='REJECT')     return '<span class="ssl-ok">p=reject</span>';
  if(s==='QUARANTINE') return '<span class="ssl-warn">p=quarantine</span>';
  if(s==='NONE')       return '<span class="ssl-bad">p=none</span>';
  if(s==='INVALIDO')   return '<span class="ssl-bad">inválido</span>';
  if(s==='AUSENTE')    return '<span class="ssl-bad">sem DMARC</span>';
  return '<span class="ssl-none">&#8212;</span>';
}
function dkimBadge(s,sel){
  if(s==='ENCONTRADO') return '<span class="ssl-ok" title="seletor: '+esc(sel||'')+'">DKIM ok</span>';
  return '<span class="ssl-none">não detectado</span>';
}
function mxBadge(b){ return b?'<span class="dnssec-on">SIM</span>':'<span class="whois-unk">&#8212;</span>'; }

// ── Mostrar/ocultar colunas (persistido por relatorio; respeitado na impressao/PDF) ──
function _colKey(){ return 'argus-cols:'+location.pathname; }
function applyColHide(hidden){
  var css=hidden.map(function(i){var n=i+1;
    return '.tbl-wrap th:nth-child('+n+'),.tbl-wrap td:nth-child('+n+'){display:none}';}).join('');
  var s=document.getElementById('col-hide');
  if(!s){ s=document.createElement('style'); s.id='col-hide'; document.head.appendChild(s); }
  s.textContent=css;
}
function initColMenu(){
  var ths=document.querySelectorAll('.tbl-wrap thead th');
  var body=document.getElementById('colmenu-body');
  if(!ths.length||!body) return;
  var hidden=[]; try{ hidden=JSON.parse(localStorage.getItem(_colKey())||'[]')||[]; }catch(e){ hidden=[]; }
  body.innerHTML='';
  ths.forEach(function(th,i){
    var label=th.textContent.replace(/[⇅↑↓▲▼]/g,'').replace(/\s+/g,' ').trim()||('Coluna '+(i+1));
    var lab=document.createElement('label');
    var cb=document.createElement('input'); cb.type='checkbox'; cb.checked=hidden.indexOf(i)===-1;
    cb.setAttribute('aria-label','Mostrar coluna '+label);
    cb.addEventListener('change',function(){
      if(cb.checked){ hidden=hidden.filter(function(x){return x!==i;}); }
      else if(hidden.indexOf(i)===-1){ hidden.push(i); }
      try{ localStorage.setItem(_colKey(),JSON.stringify(hidden)); }catch(e){}
      applyColHide(hidden);
    });
    lab.appendChild(cb); lab.appendChild(document.createTextNode(' '+label));
    body.appendChild(lab);
  });
  applyColHide(hidden);
}
document.addEventListener('DOMContentLoaded', initColMenu);

// ── Indicador de scroll horizontal: realça a borda e mostra dica quando há
//    colunas fora da área visível; some ao chegar nas extremidades. ──
function initScrollHints(){
  document.querySelectorAll('.tbl-wrap').forEach(function(w){
    var hint=document.createElement('div');
    hint.className='scroll-hint';
    hint.innerHTML='⇄ role para ver mais colunas';
    w.parentNode.insertBefore(hint, w.nextSibling);
    function upd(){
      var max=w.scrollWidth-w.clientWidth;
      var right = max>4 && (max-w.scrollLeft)>4;
      w.classList.toggle('sx-right', right);
      w.classList.toggle('sx-left', w.scrollLeft>4);
      hint.classList.toggle('show', right);
    }
    upd();
    w.addEventListener('scroll', upd, {passive:true});
    window.addEventListener('resize', upd);
  });
}
document.addEventListener('DOMContentLoaded', initScrollHints);

// ── Acessibilidade de tabela: scope nos cabeçalhos + caption oculto p/ leitor de tela. ──
function initTableA11y(){
  document.querySelectorAll('.tbl-wrap table').forEach(function(t){
    t.querySelectorAll('thead th').forEach(function(th){ if(!th.getAttribute('scope')) th.setAttribute('scope','col'); });
    if(!t.querySelector('caption')){
      var cap=document.createElement('caption'); cap.className='sr-only';
      var h1=document.querySelector('h1.page-title');
      cap.textContent='Tabela de '+((h1&&h1.textContent.trim())||'resultados')+'. Use as setas para navegar; clique nos cabeçalhos para ordenar.';
      t.insertBefore(cap, t.firstChild);
    }
  });
}
document.addEventListener('DOMContentLoaded', initTableA11y);
"""


# ============================================================
# RELATÓRIO MONITOR (portas)
# ============================================================

def _monitor_rows_to_js(rows: list[dict]) -> str:
    safe = []
    for r in rows:
        safe.append({
            "campanha":    str(r.get("campanha",    "")),
            "target":      str(r.get("target",      "")),
            "resolved_ip": str(r.get("resolved_ip", "")),
            "ip":          str(r.get("ip",          "")),
            "ip_type":     str(r.get("ip_type",     "")),
            "port":        str(r.get("port",        "")),
            "protocol":    str(r.get("protocol",    "")),
            "service":     str(r.get("service",     "")),
            "banner":      str(r.get("banner",      "")),
            "asn":         str(r.get("asn",         "")),
            "risk":        str(r.get("risk",        "BAIXO")),
            "status":      str(r.get("status",      "")),
            "ack_reason":  str(r.get("ack_reason",  "")),
            "abuse":       _abuse_to_js(r.get("abuse")),
            "internetdb":  _internetdb_to_js(r.get("internetdb")),
            "kev":         _kev_to_js(r.get("kev")),
            "nvd":         _nvd_to_js(r.get("nvd")),
        })
    return json.dumps(safe, ensure_ascii=False).replace("<", "\\u003c")


def generate_monitor_report(
    novos: list[dict],
    reincidentes: list[dict],
    corrigidos: list[dict],
    output_path: str = "monitor_report.html",
    threatintel_available: bool = False,
) -> None:
    """Gera relatório HTML do monitor de portas e salva em output_path."""

    now         = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_results = novos + reincidentes + corrigidos

    js_all  = _monitor_rows_to_js(all_results)
    js_novo = _monitor_rows_to_js(novos)
    js_rein = _monitor_rows_to_js(reincidentes)
    js_corr = _monitor_rows_to_js(corrigidos)

    total_critico  = sum(1 for r in all_results if r.get("risk") == "CRITICO")
    total_alto     = sum(1 for r in all_results if r.get("risk") == "ALTO")
    total_medio    = sum(1 for r in all_results if r.get("risk") == "MEDIO")
    total_ips      = len({r.get("ip") for r in all_results if r.get("ip")})
    total_abusivos = sum(
        1 for r in all_results
        if r.get("abuse") and (r["abuse"].get("abuse_confidence_score") or 0) >= 50
    )
    campanhas_js = json.dumps(
        sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
        ensure_ascii=False
    ).replace("<", "\\u003c")
    intel_badge = "(+ AbuseIPDB)" if threatintel_available else "(sem AbuseIPDB)"
    css = _common_css()
    js_utils = _common_js_utils()

    sev_counts = {s: sum(1 for r in all_results if r.get("risk") == s)
                  for s in ("CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO")}
    total_udp      = sum(1 for r in all_results if r.get("protocol") == "udp")
    total_tcp      = sum(1 for r in all_results if r.get("protocol") == "tcp")
    total_vuln_ips = len({r.get("ip") for r in all_results
                          if (r.get("internetdb") or {}).get("vuln_count", 0)})
    total_kev = len({r.get("ip") for r in all_results
                     if (r.get("kev") or {}).get("kev_count", 0)})
    topbar = _topbar("monitor")
    kpis = _kpi_tiles([
        (len(novos),        "Novos",          "sev-novo"),
        (len(reincidentes), "Reincidentes",   "sev-rein"),
        (len(corrigidos),   "Corrigidos",     ""),
        (total_critico,     "Críticos",       "sev-crit"),
        (total_alto,        "Alto Risco",     "sev-alto"),
        (total_vuln_ips,    "IPs vulneráveis","sev-crit" if total_vuln_ips else ""),
        (total_kev,         "IPs com KEV",    "sev-crit" if total_kev else ""),
        (total_ips,         "IPs únicos",     ""),
        (total_tcp,         "Portas TCP",     ""),
        (total_udp,         "Portas UDP",     ""),
        (total_abusivos,    "IPs Abusivos",   "sev-abus"),
    ])
    donut = _donut(sev_counts)
    exec_panel = _exec_monitor(all_results)
    footer = _footer()
    kpi_json = json.dumps({
        "scope": "monitor", "now": now,
        "critico": total_critico, "alto": total_alto, "medio": total_medio,
        "baixo": sev_counts["BAIXO"], "info": sev_counts["INFO"],
        "novos": len(novos), "reincidentes": len(reincidentes), "fechados": len(corrigidos),
        "total": len(all_results), "ips": total_ips, "abusivos": total_abusivos,
        "tcp": total_tcp, "udp": total_udp, "vuln_ips": total_vuln_ips, "kev": total_kev,
        "campanhas": sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
    }, ensure_ascii=False).replace("<", "\\u003c")
    # Linhas compactas p/ o módulo de Correlação (lido client-side, como o Dashboard).
    corr_rows = json.dumps([
        {"ip": str(r.get("ip", "")), "port": r.get("port", ""), "risk": r.get("risk", "BAIXO"),
         "cve": int((r.get("internetdb") or {}).get("vuln_count", 0) or 0),
         "kev": int((r.get("kev") or {}).get("kev_count", 0) or 0),
         "cvss": float((r.get("nvd") or {}).get("max_cvss", 0) or 0)}
        for r in all_results if r.get("ip")
    ], ensure_ascii=False).replace("<", "\\u003c")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus · Monitor de Portas</title>
<link rel="icon" type="image/svg+xml" href="{_FAVICON}">
<style>{css}</style>
</head>
<body>
{topbar}
<script id="exm-kpis" type="application/json">{kpi_json}</script>
<script id="exm-rows" type="application/json">{corr_rows}</script>
<div class="wrap" id="conteudo" role="main">

<div class="page-head">
  <div>
    <h1 class="page-title">Monitor de Portas <span class="chip">{intel_badge}</span></h1>
    <div class="page-sub">Portas e serviços expostos &middot; última verificação: {now}</div>
  </div>
  <div class="actions no-print">
    <select onchange="rtExport(this.value);this.selectedIndex=0" title="Exportar para ferramentas (respeita os filtros)">
      <option value="">&#x2B07; Red Team&hellip;</option>
      <option value="ips">IPs (Nmap -iL / Nessus / OpenVAS)</option>
      <option value="hostports">host:port (Nuclei)</option>
      <option value="urls">URLs web (httpx / nuclei)</option>
    </select>
    <button class="btn btn-pdf" onclick="window.print()">Exportar PDF</button>
    <button class="btn btn-csv" onclick="exportCSV()">Exportar CSV</button>
  </div>
</div>

<div class="summary">
  {kpis}
  {donut}
</div>

{exec_panel}

<div class="tabs no-print">
  <div class="tab active" onclick="switchTab('all')"  id="tab-all" >Todos        <span class="badge" id="b-all" >{len(all_results)}</span></div>
  <div class="tab"        onclick="switchTab('novo')" id="tab-novo">Novos        <span class="badge" id="b-novo">{len(novos)}</span></div>
  <div class="tab"        onclick="switchTab('rein')" id="tab-rein">Reincidentes <span class="badge" id="b-rein">{len(reincidentes)}</span></div>
  <div class="tab"        onclick="switchTab('corr')" id="tab-corr">Corrigidos   <span class="badge" id="b-corr">{len(corrigidos)}</span></div>
</div>

<div class="toolbar no-print">
  <input type="text" id="q" aria-label="Buscar na tabela" placeholder="&#x1F50D;  Busca (IP, target, serviço, banner, ASN, ISP...)" oninput="applyFilters()">
  <select id="f-camp"   onchange="applyFilters()"><option value="">Todas as Campanhas</option></select>
  <select id="f-risk"   onchange="applyFilters()">
    <option value="">Todos os Riscos</option>
    <option>CRITICO</option><option>ALTO</option><option>MEDIO</option><option>BAIXO</option>
  </select>
  <select id="f-status" onchange="applyFilters()">
    <option value="">Todos os Status</option>
    <option>NOVO</option><option>REINCIDENTE</option><option>CORRIGIDO</option><option>RESSURGIDO</option><option>RECONHECIDO</option>
  </select>
  <details class="morefilters no-print"><summary>&#x2699; Mais filtros</summary><div class="morefilters-body">
  <select id="f-iptype" onchange="applyFilters()">
    <option value="">Público e Privado</option>
    <option value="PUBLICO">Público</option>
    <option value="PRIVADO">Privado</option>
  </select>
  <select id="f-proto"  onchange="applyFilters()">
    <option value="">TCP e UDP</option>
    <option>tcp</option><option>udp</option>
  </select>
  <select id="f-abuse"  onchange="applyFilters()">
    <option value="">Todos (reputação)</option>
    <option value="any">Com dados AbuseIPDB</option>
    <option value="clean">Score 0 (limpo)</option>
    <option value="low">Score 1-25</option>
    <option value="medium">Score 26-50</option>
    <option value="high">Score 51-75</option>
    <option value="critical">Score 76-100</option>
    <option value="tor">Node TOR</option>
  </select>
  <select id="f-vuln"   onchange="applyFilters()">
    <option value="">Vulnerabilidade (todas)</option>
    <option value="sim">Com CVE (Shodan)</option>
    <option value="nao">Sem CVE</option>
  </select>
  </div></details>
  <select id="pgsize"   aria-label="Itens por página" onchange="changePageSize()">
    <option value="50">50 por página</option>
    <option value="100">100 por página</option>
    <option value="250">250 por página</option>
    <option value="0">Todos</option>
  </select>
  <button class="btn btn-clr" onclick="clearFilters()">&#x2715; Limpar</button>
  <details class="colmenu no-print"><summary>&#x25A6; Colunas</summary><div class="colmenu-body" id="colmenu-body"></div></details>
</div>

<div class="tbl-wrap">
<table>
  <thead><tr>
    <th onclick="doSort('ip')"            >IP      <span class="si" id="si-ip"            >&#x21C5;</span></th>
    <th onclick="doSort('ip_type')"       >Tipo    <span class="si" id="si-ip_type"       >&#x21C5;</span></th>
    <th onclick="doSort('port')"          >Porta   <span class="si" id="si-port"          >&#x21C5;</span></th>
    <th onclick="doSort('protocol')"      >Proto   <span class="si" id="si-protocol"      >&#x21C5;</span></th>
    <th onclick="doSort('service')"       >Serviço <span class="si" id="si-service"       >&#x21C5;</span></th>
    <th onclick="doSort('asn')"           >ASN     <span class="si" id="si-asn"           >&#x21C5;</span></th>
    <th onclick="doSort('abuse_country')" >País    <span class="si" id="si-abuse_country" >&#x21C5;</span></th>
    <th onclick="doSort('risk')"          >Risco   <span class="si" id="si-risk"          >&#x21C5;</span></th>
    <th onclick="doSort('abuse_score')"   >Abuso   <span class="si" id="si-abuse_score"   >&#x21C5;</span></th>
  </tr></thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<div id="no-results" class="no-results" style="display:none">Nenhum resultado para os filtros aplicados.</div>
<div class="pagination no-print" id="pagination"></div>

{footer}
</div><!-- /.wrap -->

<script>
{js_utils}
const DATA = {{all:{js_all},novo:{js_novo},rein:{js_rein},corr:{js_corr}}};
const CAMPANHAS = {campanhas_js};
const RISK_ORDER = {{'CRITICO':0,'ALTO':1,'MEDIO':2,'BAIXO':3}};
let tab='all',filtered=[],sortKey='risk',sortAsc=true,page=1,pageSize=50;

(function(){{
  const sel=document.getElementById('f-camp');
  CAMPANHAS.forEach(c=>{{const o=document.createElement('option');o.value=c;o.textContent=c;sel.appendChild(o);}});
}})();

function init(){{filtered=[...DATA[tab]];applySort();}}
function switchTab(t){{
  tab=t;document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
  document.getElementById('tab-'+t).classList.add('active');page=1;applyFilters();
}}
function applyFilters(){{
  const q=document.getElementById('q').value.toLowerCase();
  const camp=document.getElementById('f-camp').value;
  const r=document.getElementById('f-risk').value;
  const ipt=document.getElementById('f-iptype').value;
  const st=document.getElementById('f-status').value;
  const pr=document.getElementById('f-proto').value;
  const ab=document.getElementById('f-abuse').value;
  const fv=(document.getElementById('f-vuln')||{{value:''}}).value;
  filtered=DATA[tab].filter(x=>{{
    if(camp&&x.campanha!==camp)return false;
    if(r&&x.risk!==r)return false;
    if(ipt&&x.ip_type!==ipt)return false;
    if(st&&x.status!==st)return false;
    if(pr&&x.protocol!==pr)return false;
    const vc=(x.internetdb&&x.internetdb.vuln_count)||0;
    if(fv==='sim'&&vc<1)return false;
    if(fv==='nao'&&vc>=1)return false;
    const s=x.abuse?x.abuse.score:-1;
    if(ab==='any'&&s<0)return false;
    if(ab==='clean'&&s!==0)return false;
    if(ab==='low'&&!(s>=1&&s<=25))return false;
    if(ab==='medium'&&!(s>=26&&s<=50))return false;
    if(ab==='high'&&!(s>=51&&s<=75))return false;
    if(ab==='critical'&&s<76)return false;
    if(ab==='tor'&&!(x.abuse&&x.abuse.is_tor))return false;
    if(q){{const hay=(x.campanha+x.ip+x.target+x.service+x.banner+x.asn+x.port+(x.abuse?x.abuse.isp+x.abuse.country:'')).toLowerCase();if(!hay.includes(q))return false;}}
    return true;
  }});
  page=1;applySort();
}}
function clearFilters(){{['q','f-camp','f-risk','f-iptype','f-status','f-proto','f-abuse','f-vuln'].forEach(id=>{{const e=document.getElementById(id);if(e)e.value='';}});applyFilters();}}
function doSort(k){{
  if(sortKey===k)sortAsc=!sortAsc;else{{sortKey=k;sortAsc=true;}}
  document.querySelectorAll('.si').forEach(e=>e.textContent='\\u21C5');
  const si=document.getElementById('si-'+k);if(si)si.textContent=sortAsc?'\\u2191':'\\u2193';
  page=1;applySort();
}}
function applySort(){{
  filtered.sort((a,b)=>{{
    let va=_sortVal(a,sortKey),vb=_sortVal(b,sortKey);
    if(sortKey==='risk'){{va=RISK_ORDER[va]??9;vb=RISK_ORDER[vb]??9;return sortAsc?va-vb:vb-va;}}
    if(['port','abuse_score','abuse_reports','idb_vulns'].includes(sortKey))return sortAsc?Number(va)-Number(vb):Number(vb)-Number(va);
    return sortAsc?String(va).localeCompare(String(vb)):String(vb).localeCompare(String(va));
  }});
  render();
}}
function changePageSize(){{pageSize=parseInt(document.getElementById('pgsize').value)||0;page=1;render();}}
function gotoPage(p){{
  const ps=pageSize||filtered.length||1,pages=Math.ceil(filtered.length/ps);
  page=Math.max(1,Math.min(p,pages));render();window.scrollTo({{top:0,behavior:'smooth'}});
}}
function render(){{
  const tbody=document.getElementById('tbody');
  const noRes=document.getElementById('no-results');
  const pgDiv=document.getElementById('pagination');
  if(!filtered.length){{tbody.innerHTML='';noRes.style.display='block';pgDiv.innerHTML='';return;}}
  noRes.style.display='none';
  const total=filtered.length,ps=pageSize||total,pages=Math.ceil(total/ps);
  if(page>pages)page=pages;
  const start=(page-1)*ps,slice=filtered.slice(start,start+ps);
  let html='';
  slice.forEach(r=>{{
    const ab=r.abuse||{{}};
    const score=(ab.score!==undefined)?ab.score:-1;
    const torBadge=ab.is_tor?'<span class="tor-badge">TOR</span>':'';
    const lastRpt=ab.last_reported_at?ab.last_reported_at.substring(0,10):'';
    const ackR=r.ack_reason||'';
    const idb=r.internetdb||{{}};
    const vc=idb.vuln_count||0;
    const kc=(r.kev&&r.kev.kev_count)||0;
    const kevBadge=kc>0?` <span class="kev-badge" title="${{esc((r.kev.kev_cves||[]).join(', '))}} — explorada(s) in-the-wild (CISA KEV)">KEV</span>`:'';
    const nv=r.nvd||{{}};
    const mc=nv.max_cvss||0;
    const sevC={{CRITICO:'#f43f5e',ALTO:'#fb923c',MEDIO:'#fbbf24',BAIXO:'#34d399'}}[nv.max_severity]||'#8a99b4';
    const cvssBadge=mc>0?` <span class="cve-badge" style="background:${{sevC}}22;color:${{sevC}};border-color:${{sevC}}66" title="Maior CVSS entre as CVEs do ativo (NVD/NIST) — severidade ${{esc(nv.max_severity||'')}}">CVSS ${{mc.toFixed(1)}}</span>`:'';
    const cveTitle=(idb.vulns||[]).map(function(c){{var s=(nv.scores||{{}})[c];return c+(s?(' '+s):'');}}).join(', ');
    const cveCell=vc>0
      ?`<span class="cve-badge" title="${{esc(cveTitle)}}${{(idb.vulns||[]).length<vc?' …':''}}">${{vc}} CVE${{vc>1?'s':''}}</span>`+cvssBadge+kevBadge
      :'<span class="ssl-none">&#8212;</span>';
    html+=`<tr class="r-${{esc(r.risk)}}${{r.status==='RECONHECIDO'?' ack':''}}">
      <td><code>${{esc(r.ip)}}</code></td>
      <td><span class="ip-${{esc(r.ip_type)}}">${{esc(r.ip_type)}}</span></td>
      <td><b>${{esc(r.port)}}</b></td>
      <td>${{esc(r.protocol)}}</td>
      <td>${{esc(r.service)}}</td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{esc(r.asn)}}">${{esc(r.asn)}}</td>
      <td>${{esc(ab.country||'')}}</td>
      <td class="risk-${{esc(r.risk)}}">${{esc(r.risk)}}</td>
      <td><span class="${{scoreClass(score)}}">${{scoreLabel(score)}}</span>${{torBadge}}</td>
    </tr>`;
  }});
  tbody.innerHTML=html;
  renderPagination(pgDiv,page,pages,total,start,slice.length,'gotoPage');
}}
function exportCSV(){{
  const cols=['campanha','ip','ip_type','target','port','protocol','service','banner','asn','risk','status','ack_reason','resolved_ip'];
  const abCols=['score','country','isp','usage_type','is_tor','total_reports','last_reported_at'];
  const hdr=[...cols,...abCols.map(c=>'abuse_'+c),'idb_vuln_count','idb_vulns','idb_tags'].join(',');
  const rows=filtered.map(r=>{{
    const bv=cols.map(c=>'"'+String(r[c]||'').replace(/"/g,'""')+'"');
    const ab=r.abuse||{{}};
    const av=abCols.map(c=>'"'+String(ab[c]!==undefined?ab[c]:'').replace(/"/g,'""')+'"');
    const idb=r.internetdb||{{}};
    const iv=['"'+String(idb.vuln_count||0)+'"','"'+(idb.vulns||[]).join(' ')+'"','"'+(idb.tags||[]).join(' ')+'"'];
    return [...bv,...av,...iv].join(',');
  }});
  const blob=new Blob([[hdr,...rows].join('\\n')],{{type:'text/csv;charset=utf-8;'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='monitor_report_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
}}
function rtExport(kind){{
  if(!kind) return;
  const F=filtered;
  if(kind==='ips'){{
    dl('targets_ips_'+_today()+'.txt', uniq(F.map(r=>r.ip)).join('\\n'));
  }} else if(kind==='hostports'){{
    dl('host_port_'+_today()+'.txt', uniq(F.map(r=>r.ip+':'+r.port)).join('\\n'));
  }} else if(kind==='urls'){{
    const https=new Set([443,8443,9443,4443,10443]);
    const http=new Set([80,8080,8000,8888,8081,3000,5000,8008,8088]);
    const u=[];
    F.forEach(r=>{{ const p=Number(r.port);
      if(https.has(p)) u.push('https://'+r.ip+':'+p);
      else if(http.has(p)) u.push('http://'+r.ip+':'+p); }});
    if(!u.length){{ alert('Nenhuma porta web (80/443/8080/8443...) no conjunto filtrado.'); return; }}
    dl('urls_web_'+_today()+'.txt', uniq(u).join('\\n'));
  }}
}}
init();
</script>
</body>
</html>"""

    try:
        Path(output_path).write_text(html, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Falha ao gravar relatório HTML: {exc}") from exc


# ============================================================
# RELATÓRIO SUBMONITOR (subdomínios)
# ============================================================

def _submonitor_rows_to_js(rows: list[dict]) -> str:
    safe = []
    for r in rows:
        safe.append({
            "campanha":    str(r.get("campanha",    "")),
            "hostname":    str(r.get("hostname",    "")),
            "ip":          str(r.get("ip",          "")),
            "cname":       str(r.get("cname",       "-")),
            "asn":         str(r.get("asn",         "")),
            "ip_type":     str(r.get("ip_type",     "")),
            "http_status": str(r.get("http_status", "")),
            "risk":        str(r.get("risk",        "INFO")),
            "status":      str(r.get("status",      "")),
            "ack_reason":  str(r.get("ack_reason",  "")),
            "dnssec":      str(r.get("dnssec",      "DESABILITADO")),
            "ssl_status":  str((r.get("ssl") or {}).get("status", r.get("ssl_status","SEM CERTIFICADO"))),
            "ssl_expiry":  str((r.get("ssl") or {}).get("expiry_date", r.get("ssl_expiry",""))),
            "origem":      str(r.get("origem",      "wordlist")),
            "whois_creation":  str((r.get("whois") or {}).get("creation_date",   r.get("whois_creation",""))),
            "whois_expiry":    str((r.get("whois") or {}).get("expiration_date", r.get("whois_expiry",""))),
            "whois_age_days":  ((r.get("whois") or {}).get("age_days") if (r.get("whois") or {}).get("age_days") is not None else r.get("whois_age_days",-1)),
            "whois_status":    str((r.get("whois") or {}).get("status",          r.get("whois_status","DESCONHECIDO"))),
            "whois_registrar": str((r.get("whois") or {}).get("registrar",       r.get("whois_registrar",""))),
            "abuse":       _abuse_to_js(r.get("abuse")),
            "urlscan":     _urlscan_to_js(r.get("urlscan")),
            "internetdb":  _internetdb_to_js(r.get("internetdb")),
            "kev":         _kev_to_js(r.get("kev")),
            "nvd":         _nvd_to_js(r.get("nvd")),
        })
    return json.dumps(safe, ensure_ascii=False).replace("<", "\\u003c")


def generate_submonitor_report(
    novos: list[dict],
    reincidentes: list[dict],
    removidos: list[dict],
    output_path: str = "submonitor_report.html",
    threatintel_available: bool = False,
) -> None:
    """Gera relatório HTML do submonitor e salva em output_path."""

    now         = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_results = novos + reincidentes + removidos

    js_all  = _submonitor_rows_to_js(all_results)
    js_novo = _submonitor_rows_to_js(novos)
    js_rein = _submonitor_rows_to_js(reincidentes)
    js_rem  = _submonitor_rows_to_js(removidos)

    total_critico  = sum(1 for r in all_results if r.get("risk") == "CRITICO")
    total_alto     = sum(1 for r in all_results if r.get("risk") == "ALTO")
    total_medio    = sum(1 for r in all_results if r.get("risk") == "MEDIO")
    total_abusivos = sum(
        1 for r in all_results
        if r.get("abuse") and (r["abuse"].get("abuse_confidence_score") or 0) >= 50
    )
    campanhas_js = json.dumps(
        sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
        ensure_ascii=False
    ).replace("<", "\\u003c")
    intel_badge = "(+ AbuseIPDB)" if threatintel_available else "(sem AbuseIPDB)"
    css = _common_css()
    js_utils = _common_js_utils()

    total_urlscan = sum(1 for r in all_results if (r.get("urlscan") or {}).get("seen"))
    sev_counts = {s: sum(1 for r in all_results if r.get("risk") == s)
                  for s in ("CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO")}
    topbar = _topbar("submonitor")
    kpis = _kpi_tiles([
        (len(novos),        "Novos",         "sev-novo"),
        (len(reincidentes), "Reincidentes",  "sev-rein"),
        (len(removidos),    "Corrigidos",    ""),
        (total_critico,     "Críticos",      "sev-crit"),
        (total_alto,        "Alto Risco",    "sev-alto"),
        (total_medio,       "Médio",         "sev-med"),
        (len(all_results),  "Subdomínios",   ""),
        (total_urlscan,     "Visto urlscan", ""),
        (total_abusivos,    "IPs Abusivos",  "sev-abus"),
    ])
    donut = _donut(sev_counts)
    exec_panel = _exec_submonitor(all_results)
    footer = _footer()
    kpi_json = json.dumps({
        "scope": "submonitor", "now": now,
        "critico": total_critico, "alto": total_alto, "medio": total_medio,
        "baixo": sev_counts["BAIXO"], "info": sev_counts["INFO"],
        "novos": len(novos), "reincidentes": len(reincidentes), "removidos": len(removidos),
        "total": len(all_results), "urlscan": total_urlscan, "abusivos": total_abusivos,
        "campanhas": sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
    }, ensure_ascii=False).replace("<", "\\u003c")
    # Linhas compactas p/ o módulo de Correlação (subdomínio -> IP).
    corr_rows = json.dumps([
        {"h": str(r.get("hostname", "")), "ip": str(r.get("ip", "")),
         "camp": str(r.get("campanha", "")), "risk": r.get("risk", "INFO")}
        for r in all_results if r.get("hostname") and r.get("ip")
    ], ensure_ascii=False).replace("<", "\\u003c")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus · Monitor de Subdomínios</title>
<link rel="icon" type="image/svg+xml" href="{_FAVICON}">
<style>{css}</style>
</head>
<body>
{topbar}
<script id="exm-kpis" type="application/json">{kpi_json}</script>
<script id="exm-rows" type="application/json">{corr_rows}</script>
<div class="wrap" id="conteudo" role="main">

<div class="page-head">
  <div>
    <h1 class="page-title">Monitor de Subdomínios <span class="chip">{intel_badge}</span></h1>
    <div class="page-sub">Subdomínios ativos e seus riscos &middot; última verificação: {now}</div>
  </div>
  <div class="actions no-print">
    <select onchange="rtExport(this.value);this.selectedIndex=0" title="Exportar para ferramentas (respeita os filtros)">
      <option value="">&#x2B07; Red Team&hellip;</option>
      <option value="hosts">Hosts (httpx / ffuf / gobuster)</option>
      <option value="urls">URLs vivas (nuclei / katana)</option>
      <option value="ips">IPs públicos (Nmap)</option>
    </select>
    <button class="btn btn-pdf" onclick="window.print()">Exportar PDF</button>
    <button class="btn btn-csv" onclick="exportCSV()">Exportar CSV</button>
  </div>
</div>

<div class="summary">
  {kpis}
  {donut}
</div>

{exec_panel}

<div class="tabs no-print">
  <div class="tab active" onclick="switchTab('all')"  id="tab-all" >Todos        <span class="badge" id="b-all" >{len(all_results)}</span></div>
  <div class="tab"        onclick="switchTab('novo')" id="tab-novo">Novos        <span class="badge" id="b-novo">{len(novos)}</span></div>
  <div class="tab"        onclick="switchTab('rein')" id="tab-rein">Reincidentes <span class="badge" id="b-rein">{len(reincidentes)}</span></div>
  <div class="tab"        onclick="switchTab('rem')"  id="tab-rem" >Corrigidos   <span class="badge" id="b-rem" >{len(removidos)}</span></div>
</div>

<div class="toolbar no-print">
  <input type="text" id="q" aria-label="Buscar na tabela" placeholder="&#x1F50D;  Busca (hostname, IP, ASN, ISP...)" oninput="applyFilters()">
  <select id="f-camp"   onchange="applyFilters()"><option value="">Todas as Campanhas</option></select>
  <select id="f-risk"   onchange="applyFilters()">
    <option value="">Todos os Riscos</option>
    <option>CRITICO</option><option>ALTO</option><option>MEDIO</option><option>BAIXO</option>
  </select>
  <select id="f-status" onchange="applyFilters()">
    <option value="">Todos Status</option>
    <option>NOVO</option><option>REINCIDENTE</option><option>CORRIGIDO</option><option>RESSURGIDO</option><option>RECONHECIDO</option>
  </select>
  <details class="morefilters no-print"><summary>&#x2699; Mais filtros</summary><div class="morefilters-body">
  <select id="f-ipt"    onchange="applyFilters()">
    <option value="">Público e Privado</option>
    <option value="PUBLICO">Público</option>
    <option value="PRIVADO">Privado</option>
  </select>
  <select id="f-dnssec" onchange="applyFilters()">
    <option value="">DNSSEC (todos)</option>
    <option value="HABILITADO">DNSSEC Habilitado</option>
    <option value="DESABILITADO">DNSSEC Desabilitado</option>
  </select>
  <select id="f-ssl"    onchange="applyFilters()">
    <option value="">SSL (todos)</option>
    <option value="VÁLIDO">SSL Válido</option>
    <option value="EXPIRANDO">SSL Expirando</option>
    <option value="EXPIRADO">SSL Expirado</option>
    <option value="SEM CERTIFICADO">Sem Certificado</option>
  </select>
  <select id="f-origem" onchange="applyFilters()">
    <option value="">Origem (todas)</option>
    <option value="wordlist">Wordlist</option>
    <option value="crtsh">crt.sh (CT)</option>
    <option value="urlscan">urlscan.io</option>
  </select>
  <select id="f-whois" onchange="applyFilters()">
    <option value="">Domínio (todos)</option>
    <option value="NOVO">Novo (&lt;30d)</option>
    <option value="RECENTE">Recente (&lt;1 ano)</option>
    <option value="ESTABELECIDO">Estabelecido</option>
    <option value="EXPIRANDO">Expirando</option>
    <option value="EXPIRADO">Expirado</option>
  </select>
  <select id="f-http"   onchange="applyFilters()">
    <option value="">Todos HTTP</option>
    <option>200</option><option>301</option><option>302</option>
    <option>401</option><option>403</option><option>404</option><option>500</option><option>-</option>
  </select>
  <select id="f-abuse"  onchange="applyFilters()">
    <option value="">Todos (reputação)</option>
    <option value="any">Com dados AbuseIPDB</option>
    <option value="clean">Score 0 (limpo)</option>
    <option value="low">Score 1-25</option>
    <option value="medium">Score 26-50</option>
    <option value="high">Score 51-75</option>
    <option value="critical">Score 76-100</option>
    <option value="tor">Node TOR</option>
  </select>
  </div></details>
  <select id="pgsize"   aria-label="Itens por página" onchange="changePageSize()">
    <option value="50">50 por página</option>
    <option value="100">100 por página</option>
    <option value="250">250 por página</option>
    <option value="0">Todos</option>
  </select>
  <button class="btn btn-clr" onclick="clearFilters()">&#x2715; Limpar</button>
  <details class="colmenu no-print"><summary>&#x25A6; Colunas</summary><div class="colmenu-body" id="colmenu-body"></div></details>
</div>

<div class="tbl-wrap">
<table>
  <thead><tr>
    <th onclick="doSort('campanha')"        >Campanha <span class="si" id="si-campanha"       >&#x21C5;</span></th>
    <th onclick="doSort('hostname')"        >Hostname <span class="si" id="si-hostname"       >&#x21C5;</span></th>
    <th onclick="doSort('ip')"              >IP       <span class="si" id="si-ip"             >&#x21C5;</span></th>
    <th onclick="doSort('asn')"             >ASN      <span class="si" id="si-asn"            >&#x21C5;</span></th>
    <th onclick="doSort('http_status')"     >HTTP     <span class="si" id="si-http_status"    >&#x21C5;</span></th>
    <th onclick="doSort('origem')"          >Origem   <span class="si" id="si-origem"         >&#x21C5;</span></th>
    <th onclick="doSort('risk')"            >Risco    <span class="si" id="si-risk"           >&#x21C5;</span></th>
    <th onclick="doSort('status')"          >Status   <span class="si" id="si-status"         >&#x21C5;</span></th>
  </tr></thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<div id="no-results" class="no-results" style="display:none">Nenhum resultado para os filtros aplicados.</div>
<div class="pagination no-print" id="pagination"></div>

{footer}
</div><!-- /.wrap -->

<script>
{js_utils}
const DATA = {{all:{js_all},novo:{js_novo},rein:{js_rein},rem:{js_rem}}};
const CAMPANHAS = {campanhas_js};
const RISK_ORDER = {{'CRITICO':0,'ALTO':1,'MEDIO':2,'BAIXO':3,'INFO':4}};
let tab='all',filtered=[],sortKey='risk',sortAsc=true,page=1,pageSize=50;

(function(){{
  const sel=document.getElementById('f-camp');
  CAMPANHAS.forEach(c=>{{const o=document.createElement('option');o.value=c;o.textContent=c;sel.appendChild(o);}});
}})();

function init(){{filtered=[...DATA[tab]];applySort();}}
function switchTab(t){{
  tab=t;document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
  document.getElementById('tab-'+t).classList.add('active');page=1;applyFilters();
}}
function applyFilters(){{
  const q=document.getElementById('q').value.toLowerCase();
  const camp=document.getElementById('f-camp').value;
  const risk=document.getElementById('f-risk').value;
  const ipt=document.getElementById('f-ipt').value;
  const st=document.getElementById('f-status').value;
  const http=document.getElementById('f-http').value;
  const ab=document.getElementById('f-abuse').value;
  const fdnssec=(document.getElementById('f-dnssec')||{{value:''}}).value;
  const fssl=(document.getElementById('f-ssl')||{{value:''}}).value;
  const forigem=(document.getElementById('f-origem')||{{value:''}}).value;
  const fwhois=(document.getElementById('f-whois')||{{value:''}}).value;
  filtered=DATA[tab].filter(x=>{{
    if(camp&&x.campanha!==camp)return false;
    if(risk&&x.risk!==risk)return false;
    if(ipt&&x.ip_type!==ipt)return false;
    if(st&&x.status!==st)return false;
    if(http&&x.http_status!==http)return false;
    if(fdnssec&&x.dnssec!==fdnssec)return false;
    if(forigem&&(x.origem||'wordlist')!==forigem)return false;
    if(fwhois&&(x.whois_status||'DESCONHECIDO')!==fwhois)return false;
    if(fssl){{
      const ss=x.ssl_status||'SEM CERTIFICADO';
      if(fssl==='EXPIRANDO'){{if(ss.indexOf('EXPIRANDO')<0)return false;}}
      else if(ss!==fssl)return false;
    }}
    const s=x.abuse?x.abuse.score:-1;
    if(ab==='any'&&s<0)return false;
    if(ab==='clean'&&s!==0)return false;
    if(ab==='low'&&!(s>=1&&s<=25))return false;
    if(ab==='medium'&&!(s>=26&&s<=50))return false;
    if(ab==='high'&&!(s>=51&&s<=75))return false;
    if(ab==='critical'&&s<76)return false;
    if(ab==='tor'&&!(x.abuse&&x.abuse.is_tor))return false;
    if(q){{const hay=(x.campanha+x.hostname+x.ip+x.asn+(x.abuse?x.abuse.isp+x.abuse.country:'')).toLowerCase();if(!hay.includes(q))return false;}}
    return true;
  }});
  page=1;applySort();
}}
function clearFilters(){{['q','f-camp','f-risk','f-ipt','f-status','f-http','f-abuse','f-dnssec','f-ssl','f-origem','f-whois'].forEach(id=>{{const e=document.getElementById(id);if(e)e.value='';}});applyFilters();}}
function doSort(k){{
  if(sortKey===k)sortAsc=!sortAsc;else{{sortKey=k;sortAsc=true;}}
  document.querySelectorAll('.si').forEach(e=>e.textContent='\\u21C5');
  const si=document.getElementById('si-'+k);if(si)si.textContent=sortAsc?'\\u2191':'\\u2193';
  page=1;applySort();
}}
function applySort(){{
  filtered.sort((a,b)=>{{
    let va=_sortVal(a,sortKey),vb=_sortVal(b,sortKey);
    if(sortKey==='risk'){{va=RISK_ORDER[va]??9;vb=RISK_ORDER[vb]??9;return sortAsc?va-vb:vb-va;}}
    if(['http_status','abuse_score','abuse_reports','urlscan_seen','idb_vulns'].includes(sortKey))return sortAsc?Number(va)-Number(vb):Number(vb)-Number(va);
    return sortAsc?String(va).localeCompare(String(vb)):String(vb).localeCompare(String(va));
  }});
  render();
}}
function changePageSize(){{pageSize=parseInt(document.getElementById('pgsize').value)||0;page=1;render();}}
function gotoPage(p){{
  const ps=pageSize||filtered.length||1,pages=Math.ceil(filtered.length/ps);
  page=Math.max(1,Math.min(p,pages));render();window.scrollTo({{top:0,behavior:'smooth'}});
}}
function render(){{
  const tbody=document.getElementById('tbody');
  const noRes=document.getElementById('no-results');
  const pgDiv=document.getElementById('pagination');
  if(!filtered.length){{tbody.innerHTML='';noRes.style.display='block';pgDiv.innerHTML='';return;}}
  noRes.style.display='none';
  const total=filtered.length,ps=pageSize||total,pages=Math.ceil(total/ps);
  if(page>pages)page=pages;
  const start=(page-1)*ps,slice=filtered.slice(start,start+ps);
  let html='';
  slice.forEach(r=>{{
    const ab=r.abuse||{{}};
    const score=(ab.score!==undefined)?ab.score:-1;
    const torBadge=ab.is_tor?'<span class="tor-badge">TOR</span>':'';
    const lastRpt=ab.last_reported_at?ab.last_reported_at.substring(0,10):'';
    const dnssecBadge=(r.dnssec==='HABILITADO')?'<span class="dnssec-on">HABILITADO</span>':'<span class="dnssec-off">DESABILITADO</span>';
    let sslBadge;
    const sslSt=r.ssl_status||'SEM CERTIFICADO';
    if(sslSt==='VÁLIDO') sslBadge='<span class="ssl-ok">VÁLIDO</span>';
    else if(sslSt.indexOf('EXPIRANDO')>=0) sslBadge='<span class="ssl-warn">'+esc(sslSt)+'</span>';
    else if(sslSt==='EXPIRADO') sslBadge='<span class="ssl-bad">EXPIRADO</span>';
    else sslBadge='<span class="ssl-none">'+esc(sslSt)+'</span>';
    const origemBadge=(r.origem==='crtsh')
      ?'<span class="origem-crtsh" title="Descoberto via Certificate Transparency">crt.sh</span>'
      :(r.origem==='urlscan')
      ?'<span class="origem-urlscan" title="Descoberto via urlscan.io">urlscan</span>'
      :'<span class="origem-wordlist" title="Descoberto via wordlist">wordlist</span>';
    const us=r.urlscan||{{}};
    let usCell;
    if(us.seen){{
      const ut=esc([us.server,us.asnname,us.country].filter(Boolean).join(' · ')||'Visto no urlscan.io');
      usCell='<span class="us-seen" title="'+ut+'">visto</span>'
        +(us.report_url?('<a class="us-link" href="'+esc(us.report_url)+'" target="_blank" rel="noopener" title="Abrir scan no urlscan">rel</a>'):'')
        +(us.screenshot?('<a class="us-link" href="'+esc(us.screenshot)+'" target="_blank" rel="noopener" title="Screenshot do urlscan">img</a>'):'');
    }} else {{
      usCell='<span class="whois-unk">&#8212;</span>';
    }}
    let whoisBadge;
    const ws=r.whois_status||'DESCONHECIDO';
    if(ws==='NOVO') whoisBadge='<span class="whois-novo" title="Domínio criado há menos de 30 dias">NOVO</span>';
    else if(ws==='RECENTE') whoisBadge='<span class="whois-recente">RECENTE</span>';
    else if(ws==='ESTABELECIDO') whoisBadge='<span class="whois-estab">ESTABELECIDO</span>';
    else if(ws==='EXPIRANDO') whoisBadge='<span class="whois-exp">EXPIRANDO</span>';
    else if(ws==='EXPIRADO') whoisBadge='<span class="whois-expd">EXPIRADO</span>';
    else whoisBadge='<span class="whois-unk">—</span>';
    const ageVal=(r.whois_age_days!=null&&r.whois_age_days>=0)?r.whois_age_days:'';
    const ackR=r.ack_reason||'';
    const idb=r.internetdb||{{}}; const vc=idb.vuln_count||0;
    const kc=(r.kev&&r.kev.kev_count)||0;
    const kevBadge=kc>0?` <span class="kev-badge" title="${{esc((r.kev.kev_cves||[]).join(', '))}} — explorada(s) in-the-wild (CISA KEV)">KEV</span>`:'';
    const nv=r.nvd||{{}};
    const mc=nv.max_cvss||0;
    const sevC={{CRITICO:'#f43f5e',ALTO:'#fb923c',MEDIO:'#fbbf24',BAIXO:'#34d399'}}[nv.max_severity]||'#8a99b4';
    const cvssBadge=mc>0?` <span class="cve-badge" style="background:${{sevC}}22;color:${{sevC}};border-color:${{sevC}}66" title="Maior CVSS entre as CVEs do ativo (NVD/NIST) — severidade ${{esc(nv.max_severity||'')}}">CVSS ${{mc.toFixed(1)}}</span>`:'';
    const cveTitle=(idb.vulns||[]).map(function(c){{var s=(nv.scores||{{}})[c];return c+(s?(' '+s):'');}}).join(', ');
    const cveCell=vc>0
      ?`<span class="cve-badge" title="${{esc(cveTitle)}}">${{vc}} CVE${{vc>1?'s':''}}</span>`+cvssBadge+kevBadge
      :'<span class="ssl-none">&#8212;</span>';
    html+=`<tr class="r-${{esc(r.risk)}}${{r.status==='RECONHECIDO'?' ack':''}}">
      <td><span class="camp-badge">${{esc(r.campanha)}}</span></td>
      <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{esc(r.hostname)}}">${{esc(r.hostname)}}</td>
      <td><code>${{esc(r.ip)}}</code></td>
      <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{esc(r.asn)}}">${{esc(r.asn)}}</td>
      <td>${{esc(r.http_status)}}</td>
      <td>${{origemBadge}}</td>
      <td class="risk-${{esc(r.risk)}}">${{esc(r.risk)}}</td>
      <td><span class="status-${{esc(r.status)}}" title="${{esc(ackR)}}">${{esc(r.status)}}</span></td>
    </tr>`;
  }});
  tbody.innerHTML=html;
  renderPagination(pgDiv,page,pages,total,start,slice.length,'gotoPage');
}}
function exportCSV(){{
  const base=['campanha','hostname','ip','ip_type','cname','asn','http_status','origem','risk','status','ack_reason','dnssec','ssl_status','ssl_expiry','whois_status','whois_creation','whois_expiry','whois_age_days','whois_registrar'];
  const abCol=['score','country','isp','usage_type','is_tor','total_reports','last_reported_at'];
  const usCol=['seen','server','ip','asnname','country','scan_uuid','report_url'];
  const hdr=[...base,...abCol.map(c=>'abuse_'+c),...usCol.map(c=>'urlscan_'+c)].join(',');
  const rows=filtered.map(r=>{{
    const bv=base.map(c=>'"'+String(r[c]||'').replace(/"/g,'""')+'"');
    const ab=r.abuse||{{}};
    const av=abCol.map(c=>'"'+String(ab[c]!==undefined?ab[c]:'').replace(/"/g,'""')+'"');
    const us=r.urlscan||{{}};
    const uv=usCol.map(c=>'"'+String(us[c]!==undefined?us[c]:'').replace(/"/g,'""')+'"');
    return [...bv,...av,...uv].join(',');
  }});
  const blob=new Blob([[hdr,...rows].join('\\n')],{{type:'text/csv;charset=utf-8;'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='submonitor_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
}}
function rtExport(kind){{
  if(!kind) return;
  const F=filtered;
  if(kind==='hosts'){{
    dl('hosts_'+_today()+'.txt', uniq(F.map(r=>r.hostname)).join('\\n'));
  }} else if(kind==='ips'){{
    dl('ips_publicos_'+_today()+'.txt', uniq(F.filter(r=>r.ip_type==='PUBLICO').map(r=>r.ip)).join('\\n'));
  }} else if(kind==='urls'){{
    const live=F.filter(r=>r.http_status && r.http_status!=='-' && r.hostname);
    const u=live.map(r=>{{
      const hasCert=r.ssl_status && r.ssl_status!=='SEM CERTIFICADO';
      return (hasCert?'https://':'http://')+r.hostname;
    }});
    if(!u.length){{ alert('Nenhum host vivo (com resposta HTTP) no conjunto filtrado.'); return; }}
    dl('urls_vivas_'+_today()+'.txt', uniq(u).join('\\n'));
  }}
}}
init();
</script>
</body>
</html>"""

    try:
        Path(output_path).write_text(html, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Falha ao gravar relatório HTML: {exc}") from exc


# ============================================================
# RELATÓRIO CREDENCIAIS (infostealer — Hudson Rock)
# Unidade = domínio. Metadata-only (agregados; nunca senhas).
# ============================================================

def _credentials_rows_to_js(rows: list[dict]) -> str:
    safe = []
    for r in rows:
        urls = []
        for key in ("employees_urls", "clients_urls", "third_parties_urls"):
            for u in (r.get(key) or []):
                urls.append({
                    "url":        str(u.get("url", "") or ""),
                    "occurrence": int(u.get("occurrence", 0) or 0),
                    "type":       str(u.get("type", "") or ""),
                })
        urls.sort(key=lambda x: x["occurrence"], reverse=True)
        safe.append({
            "campanha":      str(r.get("campanha", "")),
            "domain":        str(r.get("domain", "")),
            "risk":          str(r.get("risk", "BAIXO")),
            "status":        str(r.get("status", "")),
            "ack_reason":    str(r.get("ack_reason", "")),
            "employees":     int(r.get("employees", 0) or 0),
            "users":         int(r.get("users", 0) or 0),
            "third_parties": int(r.get("third_parties", 0) or 0),
            "total":         int(r.get("total", 0) or 0),
            "urls":          urls[:12],
        })
    return json.dumps(safe, ensure_ascii=False).replace("<", "\\u003c")


def generate_credentials_report(
    novos: list[dict],
    reincidentes: list[dict],
    removidos: list[dict],
    output_path: str = "credentials_report.html",
    threatintel_available: bool = True,
) -> None:
    """Gera relatório HTML de exposição de credenciais (infostealer)."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_results = novos + reincidentes + removidos

    js_all  = _credentials_rows_to_js(all_results)
    js_novo = _credentials_rows_to_js(novos)
    js_rein = _credentials_rows_to_js(reincidentes)
    js_rem  = _credentials_rows_to_js(removidos)

    total_critico = sum(1 for r in all_results if r.get("risk") == "CRITICO")
    total_alto    = sum(1 for r in all_results if r.get("risk") == "ALTO")
    total_comp    = sum(1 for r in all_results if int(r.get("total", 0) or 0) > 0)
    total_emp     = sum(int(r.get("employees", 0) or 0) for r in all_results)
    total_users   = sum(int(r.get("users", 0) or 0) for r in all_results)
    total_apps    = len({u.get("url") for r in all_results
                         for key in ("employees_urls", "clients_urls", "third_parties_urls")
                         for u in (r.get(key) or []) if u.get("url")})
    sev_counts = {s: sum(1 for r in all_results if r.get("risk") == s)
                  for s in ("CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO")}
    campanhas_js = json.dumps(
        sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
        ensure_ascii=False
    ).replace("<", "\\u003c")

    css = _common_css()
    js_utils = _common_js_utils()
    topbar = _topbar("credentials")
    footer = _footer()
    kpis = _kpi_tiles([
        (total_comp,        "Domínios expostos", "sev-crit" if total_comp else ""),
        (total_emp,         "Funcionários",      "sev-crit" if total_emp else ""),
        (total_users,       "Usuários/clientes", "sev-alto" if total_users else ""),
        (total_apps,        "Apps expostas",     ""),
        (len(all_results),  "Domínios",          ""),
        (total_critico,     "Críticos",          "sev-crit"),
    ])
    donut = _donut(sev_counts, "Exposição por domínio")
    exec_panel = _exec_credentials(all_results)
    kpi_json = json.dumps({
        "scope": "credentials", "now": now,
        "critico": total_critico, "alto": total_alto, "medio": sev_counts["MEDIO"],
        "baixo": sev_counts["BAIXO"], "info": sev_counts["INFO"],
        "novos": len(novos), "reincidentes": len(reincidentes), "removidos": len(removidos),
        "total": len(all_results), "comprometidos": total_comp,
        "funcionarios": total_emp, "usuarios": total_users,
        "campanhas": sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
    }, ensure_ascii=False).replace("<", "\\u003c")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus · Exposição de Credenciais</title>
<link rel="icon" type="image/svg+xml" href="{_FAVICON}">
<style>{css}</style>
</head>
<body>
{topbar}
<script id="exm-kpis" type="application/json">{kpi_json}</script>
<div class="wrap" id="conteudo" role="main">

<div class="page-head">
  <div>
    <h1 class="page-title">Exposição de Credenciais <span class="chip">infostealer · Hudson Rock</span></h1>
    <div class="page-sub">Exposição de credenciais em logs de infostealer (agregado por domínio) &middot; última verificação: {now}</div>
  </div>
  <div class="actions no-print">
    <select onchange="rtExport(this.value);this.selectedIndex=0" title="Exportar (respeita os filtros)">
      <option value="">&#x2B07; Exportar&hellip;</option>
      <option value="json">JSON (Threat Intel)</option>
      <option value="apps">Apps expostas (URLs)</option>
    </select>
    <button class="btn btn-pdf" onclick="window.print()">Exportar PDF</button>
    <button class="btn btn-csv" onclick="exportCSV()">Exportar CSV</button>
  </div>
</div>

<div class="summary">
  {kpis}
  {donut}
</div>

{exec_panel}

<div class="tabs no-print">
  <div class="tab active" onclick="switchTab('all')"  id="tab-all" >Todos        <span class="badge" id="b-all" >{len(all_results)}</span></div>
  <div class="tab"        onclick="switchTab('novo')" id="tab-novo">Novos        <span class="badge" id="b-novo">{len(novos)}</span></div>
  <div class="tab"        onclick="switchTab('rein')" id="tab-rein">Reincidentes <span class="badge" id="b-rein">{len(reincidentes)}</span></div>
  <div class="tab"        onclick="switchTab('rem')"  id="tab-rem" >Corrigidos   <span class="badge" id="b-rem">{len(removidos)}</span></div>
</div>

<div class="toolbar no-print">
  <input type="text" id="q" aria-label="Buscar na tabela" placeholder="&#x1F50D;  Busca (domínio, campanha, app...)" oninput="applyFilters()">
  <select id="f-camp" onchange="applyFilters()"><option value="">Todas as Campanhas</option></select>
  <select id="f-risk" onchange="applyFilters()">
    <option value="">Todos os Riscos</option>
    <option>CRITICO</option><option>ALTO</option><option>MEDIO</option><option>BAIXO</option>
  </select>
  <select id="f-status" onchange="applyFilters()">
    <option value="">Todos os Status</option>
    <option>NOVO</option><option>REINCIDENTE</option><option>CORRIGIDO</option><option>RESSURGIDO</option><option>RECONHECIDO</option>
  </select>
  <select id="f-comp" onchange="applyFilters()">
    <option value="">Comprometidos e limpos</option>
    <option value="sim">Só comprometidos</option>
    <option value="nao">Só limpos</option>
  </select>
  <select id="pgsize" aria-label="Itens por página" onchange="changePageSize()">
    <option value="50">50 por página</option><option value="100">100 por página</option>
    <option value="250">250 por página</option><option value="0">Todos</option>
  </select>
  <button class="btn btn-clr" onclick="clearFilters()">&#x2715; Limpar</button>
  <details class="colmenu no-print"><summary>&#x25A6; Colunas</summary><div class="colmenu-body" id="colmenu-body"></div></details>
</div>

<div class="tbl-wrap">
<table>
  <thead><tr>
    <th onclick="doSort('campanha')"     >Campanha     <span class="si" id="si-campanha"     >&#x21C5;</span></th>
    <th onclick="doSort('domain')"       >Domínio      <span class="si" id="si-domain"       >&#x21C5;</span></th>
    <th onclick="doSort('risk')"         >Risco        <span class="si" id="si-risk"         >&#x21C5;</span></th>
    <th onclick="doSort('employees')"    >Funcionários <span class="si" id="si-employees"    >&#x21C5;</span></th>
    <th onclick="doSort('users')"        >Usuários     <span class="si" id="si-users"        >&#x21C5;</span></th>
    <th onclick="doSort('third_parties')">Terceiros    <span class="si" id="si-third_parties">&#x21C5;</span></th>
    <th onclick="doSort('total')"        >Total        <span class="si" id="si-total"        >&#x21C5;</span></th>
    <th>Apps expostas (top)</th>
    <th onclick="doSort('status')"       >Status       <span class="si" id="si-status"       >&#x21C5;</span></th>
    <th onclick="doSort('ack_reason')"   >Motivo       <span class="si" id="si-ack_reason"   >&#x21C5;</span></th>
    <th>Origem</th>
  </tr></thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<div id="no-results" class="no-results" style="display:none">Nenhum resultado para os filtros aplicados.</div>
<div class="pagination no-print" id="pagination"></div>

{footer}
</div><!-- /.wrap -->

<script>
{js_utils}
const DATA = {{all:{js_all},novo:{js_novo},rein:{js_rein},rem:{js_rem}}};
const CAMPANHAS = {campanhas_js};
const RISK_ORDER = {{'CRITICO':0,'ALTO':1,'MEDIO':2,'BAIXO':3,'INFO':4}};
let tab='all',filtered=[],sortKey='risk',sortAsc=true,page=1,pageSize=50;

function switchTab(t){{
  tab=t; ['all','novo','rein','rem'].forEach(x=>{{
    const e=document.getElementById('tab-'+x); if(e)e.classList.toggle('active',x===t);
  }}); page=1; applyFilters();
}}
function initFilters(){{
  const sel=document.getElementById('f-camp');
  CAMPANHAS.forEach(c=>{{const o=document.createElement('option');o.value=c;o.textContent=c;sel.appendChild(o);}});
}}
function applyFilters(){{
  const q=(document.getElementById('q').value||'').toLowerCase().trim();
  const camp=document.getElementById('f-camp').value;
  const risk=document.getElementById('f-risk').value;
  const st=document.getElementById('f-status').value;
  const comp=document.getElementById('f-comp').value;
  filtered=DATA[tab].filter(x=>{{
    if(camp&&x.campanha!==camp)return false;
    if(risk&&x.risk!==risk)return false;
    if(st&&x.status!==st)return false;
    if(comp==='sim'&&!(x.total>0))return false;
    if(comp==='nao'&&x.total>0)return false;
    if(q){{const hay=(x.campanha+x.domain+(x.urls||[]).map(u=>u.url).join(' ')).toLowerCase();if(!hay.includes(q))return false;}}
    return true;
  }});
  page=1; applySort();
}}
function clearFilters(){{['q','f-camp','f-risk','f-status','f-comp'].forEach(id=>{{const e=document.getElementById(id);if(e)e.value='';}});applyFilters();}}
function doSort(k){{
  if(sortKey===k)sortAsc=!sortAsc;else{{sortKey=k;sortAsc=true;}}
  document.querySelectorAll('.si').forEach(e=>e.textContent='\\u21C5');
  const si=document.getElementById('si-'+k);if(si)si.textContent=sortAsc?'\\u2191':'\\u2193';
  page=1;applySort();
}}
function applySort(){{
  filtered.sort((a,b)=>{{
    let va=_sortVal(a,sortKey),vb=_sortVal(b,sortKey);
    if(sortKey==='risk'){{va=RISK_ORDER[va]??9;vb=RISK_ORDER[vb]??9;return sortAsc?va-vb:vb-va;}}
    if(['employees','users','third_parties','total'].includes(sortKey))return sortAsc?Number(va)-Number(vb):Number(vb)-Number(va);
    return sortAsc?String(va).localeCompare(String(vb)):String(vb).localeCompare(String(va));
  }});
  render();
}}
function changePageSize(){{pageSize=parseInt(document.getElementById('pgsize').value)||0;page=1;render();}}
function gotoPage(p){{
  const ps=pageSize||filtered.length||1,pages=Math.ceil(filtered.length/ps);
  page=Math.max(1,Math.min(p,pages));render();window.scrollTo({{top:0,behavior:'smooth'}});
}}
function render(){{
  const tbody=document.getElementById('tbody');
  const noRes=document.getElementById('no-results');
  const pgDiv=document.getElementById('pagination');
  const total=filtered.length;
  const ps=pageSize||total||1, pages=Math.ceil(total/ps);
  if(page>pages)page=pages;
  const start=(page-1)*ps,slice=filtered.slice(start,start+ps);
  noRes.style.display=total?'none':'block';
  let html='';
  slice.forEach(r=>{{
    const apps=r.urls||[];
    const appsCell = apps.length
      ? '<span title="'+esc(apps.map(u=>u.occurrence+'x '+u.url).join('  '))+'">'
        +esc(apps[0].url.replace(/^https?:\\/\\//,'').slice(0,44))
        +(apps.length>1?(' <span class="badge">+'+(apps.length-1)+'</span>'):'')+'</span>'
      : '<span class="whois-unk">&#8212;</span>';
    const empCell=r.employees>0?('<span class="b-crit">'+r.employees+'</span>'):'0';
    const usrCell=r.users>0?('<span class="whois-recente">'+r.users+'</span>'):'0';
    const ackR=r.ack_reason||'';
    html+=`<tr class="r-${{esc(r.risk)}}${{r.status==='RECONHECIDO'?' ack':''}}">
      <td><span class="camp-badge">${{esc(r.campanha)}}</span></td>
      <td><code>${{esc(r.domain)}}</code></td>
      <td class="risk-${{esc(r.risk)}}">${{esc(r.risk)}}</td>
      <td>${{empCell}}</td>
      <td>${{usrCell}}</td>
      <td>${{r.third_parties||0}}</td>
      <td><b>${{r.total||0}}</b></td>
      <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${{appsCell}}</td>
      <td><span class="status-${{esc(r.status)}}" title="${{esc(ackR)}}">${{esc(r.status)}}</span></td>
      <td>${{ackR?`<span class="ack-reason" title="${{esc(ackR)}}">${{esc(ackR)}}</span>`:''}}</td>
      <td><span class="origem-urlscan">Hudson Rock</span></td>
    </tr>`;
  }});
  tbody.innerHTML=html;
  renderPagination(pgDiv,page,pages,total,start,slice.length,'gotoPage');
}}
function exportCSV(){{
  const cols=['campanha','domain','risk','status','ack_reason','employees','users','third_parties','total'];
  const hdr=[...cols,'top_apps'].join(',');
  const rows=filtered.map(r=>{{
    const bv=cols.map(c=>'"'+String(r[c]!==undefined?r[c]:'').replace(/"/g,'""')+'"');
    const apps=(r.urls||[]).map(u=>u.occurrence+'x '+u.url).join(' | ');
    return [...bv,'"'+apps.replace(/"/g,'""')+'"'].join(',');
  }});
  const blob=new Blob([[hdr,...rows].join('\\n')],{{type:'text/csv;charset=utf-8;'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='credentials_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
}}
function rtExport(kind){{
  if(!kind) return;
  const F=filtered;
  if(kind==='json'){{
    dl('credentials_'+_today()+'.json', JSON.stringify(F,null,2), 'application/json');
  }} else if(kind==='apps'){{
    const u=[];
    F.forEach(r=>(r.urls||[]).forEach(x=>{{ if(x.url) u.push(x.url); }}));
    if(!u.length){{ alert('Nenhuma app exposta no conjunto filtrado.'); return; }}
    dl('apps_expostas_'+_today()+'.txt', uniq(u).join('\\n'));
  }}
}}
function init(){{initFilters();applyFilters();}}
init();
</script>
</body>
</html>"""

    try:
        Path(output_path).write_text(html, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Falha ao gravar relatório HTML: {exc}") from exc


# ============================================================
# RELATÓRIO E-MAIL (postura SPF / DMARC / DKIM)
# ============================================================

def _email_rows_to_js(rows: list[dict]) -> str:
    safe = []
    for r in rows:
        safe.append({
            "campanha":      str(r.get("campanha", "")),
            "domain":        str(r.get("domain", "")),
            "has_mx":        bool(r.get("has_mx", False)),
            "mx":            str(r.get("mx", "")),
            "spf_status":    str(r.get("spf_status", "")),
            "spf_raw":       str(r.get("spf_raw", "")),
            "dmarc_status":  str(r.get("dmarc_status", "")),
            "dmarc_raw":     str(r.get("dmarc_raw", "")),
            "dkim_status":   str(r.get("dkim_status", "")),
            "dkim_selector": str(r.get("dkim_selector", "")),
            "risk":          str(r.get("risk", "INFO")),
            "status":        str(r.get("status", "")),
            "ack_reason":    str(r.get("ack_reason", "")),
            "issues":        [str(x) for x in (r.get("issues") or [])],
        })
    return json.dumps(safe, ensure_ascii=False).replace("<", "\\u003c")


def generate_email_report(
    novos: list[dict],
    reincidentes: list[dict],
    removidos: list[dict],
    output_path: str = "email_report.html",
    threatintel_available: bool = False,
) -> None:
    """Gera relatório HTML da postura de e-mail (SPF/DMARC/DKIM/MX) por domínio."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_results = novos + reincidentes + removidos

    js_all  = _email_rows_to_js(all_results)
    js_novo = _email_rows_to_js(novos)
    js_rein = _email_rows_to_js(reincidentes)
    js_rem  = _email_rows_to_js(removidos)

    total_critico = sum(1 for r in all_results if r.get("risk") == "CRITICO")
    total_alto    = sum(1 for r in all_results if r.get("risk") == "ALTO")
    spoofaveis    = total_critico + total_alto
    sem_spf       = sum(1 for r in all_results if r.get("spf_status") == "AUSENTE")
    sem_dmarc     = sum(1 for r in all_results if r.get("dmarc_status") in ("AUSENTE", "NONE"))
    com_mx        = sum(1 for r in all_results if r.get("has_mx"))
    sev_counts = {s: sum(1 for r in all_results if r.get("risk") == s)
                  for s in ("CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO")}
    campanhas_js = json.dumps(
        sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
        ensure_ascii=False
    ).replace("<", "\\u003c")

    css = _common_css()
    js_utils = _common_js_utils()
    topbar = _topbar("email")
    footer = _footer()
    kpis = _kpi_tiles([
        (spoofaveis,        "Spoofáveis",       "sev-crit" if spoofaveis else ""),
        (sem_dmarc,         "Sem DMARC eficaz", "sev-alto" if sem_dmarc else ""),
        (sem_spf,           "Sem SPF",          "sev-alto" if sem_spf else ""),
        (com_mx,            "Recebem e-mail",   ""),
        (len(all_results),  "Domínios",         ""),
        (total_critico,     "Críticos",         "sev-crit"),
    ])
    donut = _donut(sev_counts, "Postura por domínio")
    exec_panel = _exec_email(all_results)
    kpi_json = json.dumps({
        "scope": "email", "now": now,
        "critico": total_critico, "alto": total_alto, "medio": sev_counts["MEDIO"],
        "baixo": sev_counts["BAIXO"], "info": sev_counts["INFO"],
        "novos": len(novos), "reincidentes": len(reincidentes), "removidos": len(removidos),
        "total": len(all_results), "spoofaveis": spoofaveis,
        "sem_spf": sem_spf, "sem_dmarc": sem_dmarc, "com_mx": com_mx,
        "campanhas": sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
    }, ensure_ascii=False).replace("<", "\\u003c")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus · Postura de E-mail</title>
<link rel="icon" type="image/svg+xml" href="{_FAVICON}">
<style>{css}</style>
</head>
<body>
{topbar}
<script id="exm-kpis" type="application/json">{kpi_json}</script>
<div class="wrap" id="conteudo" role="main">

<div class="page-head">
  <div>
    <h1 class="page-title">Postura de E-mail <span class="chip">SPF · DMARC · DKIM</span></h1>
    <div class="page-sub">Anti-spoofing por domínio (autenticação de e-mail) &middot; última verificação: {now}</div>
  </div>
  <div class="actions no-print">
    <select onchange="rtExport(this.value);this.selectedIndex=0" title="Exportar (respeita os filtros)">
      <option value="">&#x2B07; Exportar&hellip;</option>
      <option value="json">JSON (Threat Intel)</option>
      <option value="spoof">Domínios spoofáveis (.txt)</option>
    </select>
    <button class="btn btn-pdf" onclick="window.print()">Exportar PDF</button>
    <button class="btn btn-csv" onclick="exportCSV()">Exportar CSV</button>
  </div>
</div>

<div class="summary">
  {kpis}
  {donut}
</div>

{exec_panel}

<div class="tabs no-print">
  <div class="tab active" onclick="switchTab('all')"  id="tab-all" >Todos        <span class="badge" id="b-all" >{len(all_results)}</span></div>
  <div class="tab"        onclick="switchTab('novo')" id="tab-novo">Novos        <span class="badge" id="b-novo">{len(novos)}</span></div>
  <div class="tab"        onclick="switchTab('rein')" id="tab-rein">Reincidentes <span class="badge" id="b-rein">{len(reincidentes)}</span></div>
  <div class="tab"        onclick="switchTab('rem')"  id="tab-rem" >Corrigidos   <span class="badge" id="b-rem">{len(removidos)}</span></div>
</div>

<div class="toolbar no-print">
  <input type="text" id="q" aria-label="Buscar na tabela" placeholder="&#x1F50D;  Busca (domínio, campanha, problema...)" oninput="applyFilters()">
  <select id="f-camp" onchange="applyFilters()"><option value="">Todas as Campanhas</option></select>
  <select id="f-risk" onchange="applyFilters()">
    <option value="">Todos os Riscos</option>
    <option>CRITICO</option><option>ALTO</option><option>MEDIO</option><option>BAIXO</option><option>INFO</option>
  </select>
  <select id="f-status" onchange="applyFilters()">
    <option value="">Todos os Status</option>
    <option>NOVO</option><option>REINCIDENTE</option><option>CORRIGIDO</option><option>RESSURGIDO</option><option>RECONHECIDO</option>
  </select>
  <select id="f-mx" onchange="applyFilters()">
    <option value="">Recebe e-mail (todos)</option>
    <option value="sim">Com MX</option>
    <option value="nao">Sem MX</option>
  </select>
  <select id="pgsize" aria-label="Itens por página" onchange="changePageSize()">
    <option value="50">50 por página</option><option value="100">100 por página</option>
    <option value="250">250 por página</option><option value="0">Todos</option>
  </select>
  <button class="btn btn-clr" onclick="clearFilters()">&#x2715; Limpar</button>
  <details class="colmenu no-print"><summary>&#x25A6; Colunas</summary><div class="colmenu-body" id="colmenu-body"></div></details>
</div>

<div class="tbl-wrap">
<table>
  <thead><tr>
    <th onclick="doSort('campanha')"     >Campanha     <span class="si" id="si-campanha"    >&#x21C5;</span></th>
    <th onclick="doSort('domain')"       >Domínio      <span class="si" id="si-domain"      >&#x21C5;</span></th>
    <th onclick="doSort('has_mx')"       >MX           <span class="si" id="si-has_mx"      >&#x21C5;</span></th>
    <th onclick="doSort('spf_status')"   >SPF          <span class="si" id="si-spf_status"  >&#x21C5;</span></th>
    <th onclick="doSort('dmarc_status')" >DMARC        <span class="si" id="si-dmarc_status">&#x21C5;</span></th>
    <th onclick="doSort('dkim_status')"  >DKIM         <span class="si" id="si-dkim_status" >&#x21C5;</span></th>
    <th onclick="doSort('risk')"         >Risco        <span class="si" id="si-risk"        >&#x21C5;</span></th>
    <th onclick="doSort('status')"       >Status       <span class="si" id="si-status"      >&#x21C5;</span></th>
    <th onclick="doSort('ack_reason')"   >Motivo       <span class="si" id="si-ack_reason"  >&#x21C5;</span></th>
    <th>Problemas</th>
  </tr></thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<div id="no-results" class="no-results" style="display:none">Nenhum resultado para os filtros aplicados.</div>
<div class="pagination no-print" id="pagination"></div>

{footer}
</div><!-- /.wrap -->

<script>
{js_utils}
const DATA = {{all:{js_all},novo:{js_novo},rein:{js_rein},rem:{js_rem}}};
const CAMPANHAS = {campanhas_js};
const RISK_ORDER = {{'CRITICO':0,'ALTO':1,'MEDIO':2,'BAIXO':3,'INFO':4}};
let tab='all',filtered=[],sortKey='risk',sortAsc=true,page=1,pageSize=50;

function switchTab(t){{
  tab=t; ['all','novo','rein','rem'].forEach(x=>{{
    const e=document.getElementById('tab-'+x); if(e)e.classList.toggle('active',x===t);
  }}); page=1; applyFilters();
}}
function initFilters(){{
  const sel=document.getElementById('f-camp');
  CAMPANHAS.forEach(c=>{{const o=document.createElement('option');o.value=c;o.textContent=c;sel.appendChild(o);}});
}}
function applyFilters(){{
  const q=(document.getElementById('q').value||'').toLowerCase().trim();
  const camp=document.getElementById('f-camp').value;
  const risk=document.getElementById('f-risk').value;
  const st=document.getElementById('f-status').value;
  const mx=document.getElementById('f-mx').value;
  filtered=DATA[tab].filter(x=>{{
    if(camp&&x.campanha!==camp)return false;
    if(risk&&x.risk!==risk)return false;
    if(st&&x.status!==st)return false;
    if(mx==='sim'&&!x.has_mx)return false;
    if(mx==='nao'&&x.has_mx)return false;
    if(q){{const hay=(x.campanha+x.domain+(x.issues||[]).join(' ')).toLowerCase();if(!hay.includes(q))return false;}}
    return true;
  }});
  page=1; applySort();
}}
function clearFilters(){{['q','f-camp','f-risk','f-status','f-mx'].forEach(id=>{{const e=document.getElementById(id);if(e)e.value='';}});applyFilters();}}
function doSort(k){{
  if(sortKey===k)sortAsc=!sortAsc;else{{sortKey=k;sortAsc=true;}}
  document.querySelectorAll('.si').forEach(e=>e.textContent='\\u21C5');
  const si=document.getElementById('si-'+k);if(si)si.textContent=sortAsc?'\\u2191':'\\u2193';
  page=1;applySort();
}}
function applySort(){{
  filtered.sort((a,b)=>{{
    let va=_sortVal(a,sortKey),vb=_sortVal(b,sortKey);
    if(sortKey==='risk'){{va=RISK_ORDER[va]??9;vb=RISK_ORDER[vb]??9;return sortAsc?va-vb:vb-va;}}
    if(sortKey==='has_mx'){{return sortAsc?(a.has_mx?1:0)-(b.has_mx?1:0):(b.has_mx?1:0)-(a.has_mx?1:0);}}
    return sortAsc?String(va).localeCompare(String(vb)):String(vb).localeCompare(String(va));
  }});
  render();
}}
function changePageSize(){{pageSize=parseInt(document.getElementById('pgsize').value)||0;page=1;render();}}
function gotoPage(p){{
  const ps=pageSize||filtered.length||1,pages=Math.ceil(filtered.length/ps);
  page=Math.max(1,Math.min(p,pages));render();window.scrollTo({{top:0,behavior:'smooth'}});
}}
function render(){{
  const tbody=document.getElementById('tbody');
  const noRes=document.getElementById('no-results');
  const pgDiv=document.getElementById('pagination');
  const total=filtered.length;
  const ps=pageSize||total||1, pages=Math.ceil(total/ps);
  if(page>pages)page=pages;
  const start=(page-1)*ps,slice=filtered.slice(start,start+ps);
  noRes.style.display=total?'none':'block';
  let html='';
  slice.forEach(r=>{{
    const ackR=r.ack_reason||'';
    const issues=(r.issues||[]).join(' · ');
    html+=`<tr class="r-${{esc(r.risk)}}${{r.status==='RECONHECIDO'?' ack':''}}">
      <td><span class="camp-badge">${{esc(r.campanha)}}</span></td>
      <td><code>${{esc(r.domain)}}</code></td>
      <td>${{mxBadge(r.has_mx)}}</td>
      <td title="${{esc(r.spf_raw)}}">${{spfBadge(r.spf_status)}}</td>
      <td title="${{esc(r.dmarc_raw)}}">${{dmarcBadge(r.dmarc_status)}}</td>
      <td>${{dkimBadge(r.dkim_status,r.dkim_selector)}}</td>
      <td class="risk-${{esc(r.risk)}}">${{esc(r.risk)}}</td>
      <td><span class="status-${{esc(r.status)}}" title="${{esc(ackR)}}">${{esc(r.status)}}</span></td>
      <td>${{ackR?`<span class="ack-reason" title="${{esc(ackR)}}">${{esc(ackR)}}</span>`:''}}</td>
      <td style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{esc(issues)}}">${{esc(issues)}}</td>
    </tr>`;
  }});
  tbody.innerHTML=html;
  renderPagination(pgDiv,page,pages,total,start,slice.length,'gotoPage');
}}
function exportCSV(){{
  const cols=['campanha','domain','has_mx','mx','spf_status','spf_raw','dmarc_status','dmarc_raw','dkim_status','dkim_selector','risk','status','ack_reason'];
  const hdr=[...cols,'issues'].join(',');
  const rows=filtered.map(r=>{{
    const bv=cols.map(c=>'"'+String(r[c]!==undefined?r[c]:'').replace(/"/g,'""')+'"');
    const iss=(r.issues||[]).join(' | ');
    return [...bv,'"'+iss.replace(/"/g,'""')+'"'].join(',');
  }});
  const blob=new Blob([[hdr,...rows].join('\\n')],{{type:'text/csv;charset=utf-8;'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='email_posture_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
}}
function rtExport(kind){{
  if(!kind) return;
  const F=filtered;
  if(kind==='json'){{
    dl('email_posture_'+_today()+'.json', JSON.stringify(F,null,2), 'application/json');
  }} else if(kind==='spoof'){{
    const d=uniq(F.filter(r=>r.risk==='CRITICO'||r.risk==='ALTO').map(r=>r.domain));
    if(!d.length){{ alert('Nenhum domínio spoofável (crítico/alto) no conjunto filtrado.'); return; }}
    dl('dominios_spoofaveis_'+_today()+'.txt', d.join('\\n'));
  }}
}}
function init(){{initFilters();applyFilters();}}
init();
</script>
</body>
</html>"""

    try:
        Path(output_path).write_text(html, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Falha ao gravar relatório HTML: {exc}") from exc


# ============================================================
# PORTAL ESTÁTICO (index / dashboard / guia de risco)
# Gerado em Python para manter UMA fonte de design (app.css = _common_css()).
# ============================================================

def app_css() -> str:
    """CSS canônico do produto (alias público de _common_css)."""
    return _common_css()


def _portal_shell(active: str, title: str, subtitle: str, body: str,
                  extra_script: str = "", show_head: bool = True) -> str:
    """Casca padrão de página do portal (link p/ /assets/app.css + topbar + footer)."""
    _ttl = "Argus" if (not title or title == "Argus") else f"{title} — Argus"
    head = (
        '<!DOCTYPE html>\n<html lang="pt-BR">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f'<title>{_ttl}</title>\n'
        f'<link rel="icon" type="image/svg+xml" href="{_FAVICON}">\n'
        '<link rel="stylesheet" href="/assets/app.css">\n'
        '</head>\n<body>\n'
    )
    page_head = ""
    if show_head:
        page_head = (
            '<div class="page-head"><div>'
            f'<h1 class="page-title">{title}</h1>'
            f'<div class="page-sub">{subtitle}</div>'
            '</div></div>\n'
        )
    return (
        head + _topbar(active) + '\n<main class="wrap" id="conteudo">\n'
        + page_head + body + '\n' + _footer() + '\n</main>\n'
        + extra_script + '\n</body>\n</html>\n'
    )


# ============================================================
# RELATÓRIO — TYPOSQUAT (domínios sósia / dnstwist)
# ============================================================

def _typosquat_rows_to_js(rows: list[dict]) -> str:
    safe = []
    for r in rows:
        safe.append({
            "campanha":    str(r.get("campanha", "")),
            "base_domain": str(r.get("base_domain", "")),
            "domain":      str(r.get("domain", "")),
            "fuzzer":      str(r.get("fuzzer", "")),
            "ip":          str(r.get("ip", "")),
            "mx":          bool(r.get("mx", False)),
            "risk":        str(r.get("risk", "MEDIO")),
            "status":      str(r.get("status", "")),
            "ack_reason":  str(r.get("ack_reason", "")),
            "whois_status":   str(r.get("whois_status", "") or "DESCONHECIDO"),
            "whois_creation": str(r.get("whois_creation", "") or ""),
            "whois_age_days": int(r.get("whois_age_days")) if isinstance(r.get("whois_age_days"), int) and r.get("whois_age_days") >= 0 else -1,
        })
    return json.dumps(safe, ensure_ascii=False).replace("<", "\\u003c")


def _exec_typosquat(all_results: list) -> str:
    cur   = [r for r in all_results if r.get("status") in ("NOVO", "REINCIDENTE")]
    ncamp = len({r.get("campanha") for r in cur if r.get("campanha")})
    tc    = sum(1 for r in cur if r.get("risk") == "CRITICO")
    ta    = sum(1 for r in cur if r.get("risk") == "ALTO")
    lead  = (f"{len(cur)} domínio(s) sósia registrado(s) em {ncamp} campanha(s). " +
             (f"<b>{tc} pronto(s) para phishing</b> (resolve + MX) e {ta} resolvendo a um IP exigem ação."
              if (tc or ta) else "Nenhum sósia de alto risco nesta execução."))
    cur.sort(key=lambda r: _SEV_RANK.get(r.get("risk"), 5))
    risks = []
    for r in cur[:5]:
        sv = r.get("risk")
        if sv not in ("CRITICO", "ALTO", "MEDIO"):
            continue
        risks.append(f'<span class="sv risk-{sv}">{sv}</span> {_h(r.get("domain"))} '
                     f'<span class="page-sub">(sósia de {_h(r.get("base_domain"))} · {_h(r.get("fuzzer"))})</span>')
    recs = []
    def add(c):
        if c not in recs: recs.append(c)
    nr = sum(1 for r in cur if str(r.get("whois_status", "")) in ("NOVO", "RECENTE"))
    if tc: add("Sósia com MX ativo = capaz de receber e-mail — risco direto de phishing/BEC. Acione takedown e monitore.")
    if ta: add("Sósia resolvendo a um IP pode hospedar página clonada — verifique conteúdo e considere takedown.")
    if nr: add(f"{nr} sósia(s) registrado(s) recentemente (coluna Registro = NOVO/RECENTE) — domínio sósia novo costuma indicar campanha em preparação; priorize a verificação.")
    add("Registre o tratamento de cada sósia (confirmar/mitigar/falso-positivo) em Gestão de Achados.")
    add("Avalie registrar defensivamente as permutações mais críticas da sua marca.")
    return _exec_panel(lead, risks, recs)


def generate_typosquat_report(
    novos: list[dict], reincidentes: list[dict], removidos: list[dict],
    output_path: str = "typosquat_report.html", threatintel_available: bool = False,
) -> None:
    """Relatório de typosquatting/homoglyph (domínios sósia registrados, dnstwist)."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    all_results = novos + reincidentes + removidos
    js_all  = _typosquat_rows_to_js(all_results)
    js_novo = _typosquat_rows_to_js(novos)
    js_rein = _typosquat_rows_to_js(reincidentes)
    js_rem  = _typosquat_rows_to_js(removidos)

    total_crit = sum(1 for r in all_results if r.get("risk") == "CRITICO")
    total_alto = sum(1 for r in all_results if r.get("risk") == "ALTO")
    com_mx     = sum(1 for r in all_results if r.get("mx"))
    com_ip     = sum(1 for r in all_results if r.get("ip"))
    recent_reg = sum(1 for r in all_results if str(r.get("whois_status", "")) in ("NOVO", "RECENTE"))
    sev_counts = {s: sum(1 for r in all_results if r.get("risk") == s)
                  for s in ("CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO")}
    campanhas_js = json.dumps(
        sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
        ensure_ascii=False).replace("<", "\\u003c")

    css = _common_css(); js_utils = _common_js_utils()
    topbar = _topbar("typosquat"); footer = _footer()
    kpis = _kpi_tiles([
        (total_crit,        "Pronto p/ phishing", "sev-crit"),
        (total_alto,        "Resolvendo a IP",    "sev-alto"),
        (com_mx,            "Com MX",             ""),
        (com_ip,            "Com IP",             ""),
        (len(all_results),  "Sósia",              ""),
        (recent_reg,        "Recém-registr.",     "sev-alto"),
    ])
    donut = _donut(sev_counts, "Sósia por risco")
    exec_panel = _exec_typosquat(all_results)
    kpi_json = json.dumps({
        "scope": "typosquat", "now": now,
        "critico": total_crit, "alto": total_alto, "medio": sev_counts["MEDIO"],
        "baixo": sev_counts["BAIXO"], "info": sev_counts["INFO"],
        "novos": len(novos), "reincidentes": len(reincidentes), "removidos": len(removidos),
        "total": len(all_results), "com_mx": com_mx, "com_ip": com_ip,
        "campanhas": sorted({r.get("campanha", "") for r in all_results if r.get("campanha")}),
    }, ensure_ascii=False).replace("<", "\\u003c")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus · Typosquat</title>
<link rel="icon" type="image/svg+xml" href="{_FAVICON}">
<style>{css}</style>
</head>
<body>
{topbar}
<script id="exm-kpis" type="application/json">{kpi_json}</script>
<div class="wrap" id="conteudo" role="main">

<div class="page-head">
  <div>
    <h1 class="page-title">Typosquat <span class="chip">dnstwist · homoglyph</span></h1>
    <div class="page-sub">Domínios sósia registrados (typosquatting / abuso de marca) &middot; última verificação: {now}</div>
  </div>
  <div class="actions no-print">
    <select onchange="rtExport(this.value);this.selectedIndex=0" title="Exportar (respeita os filtros)">
      <option value="">&#x2B07; Exportar&hellip;</option>
      <option value="domains">Domínios sósia (.txt)</option>
      <option value="json">JSON</option>
    </select>
    <button class="btn btn-pdf" onclick="window.print()">Exportar PDF</button>
    <button class="btn btn-csv" onclick="exportCSV()">Exportar CSV</button>
  </div>
</div>

<div class="summary">
  {kpis}
  {donut}
</div>

{exec_panel}

<div class="tabs no-print">
  <div class="tab active" onclick="switchTab('all')"  id="tab-all" >Todos        <span class="badge" id="b-all" >{len(all_results)}</span></div>
  <div class="tab"        onclick="switchTab('novo')" id="tab-novo">Novos        <span class="badge" id="b-novo">{len(novos)}</span></div>
  <div class="tab"        onclick="switchTab('rein')" id="tab-rein">Reincidentes <span class="badge" id="b-rein">{len(reincidentes)}</span></div>
  <div class="tab"        onclick="switchTab('rem')"  id="tab-rem" >Corrigidos   <span class="badge" id="b-rem">{len(removidos)}</span></div>
</div>

<div class="toolbar no-print">
  <input type="text" id="q" aria-label="Buscar na tabela" placeholder="&#x1F50D;  Busca (sósia, base, técnica, IP...)" oninput="applyFilters()">
  <select id="f-camp" onchange="applyFilters()"><option value="">Todas as Campanhas</option></select>
  <select id="f-risk" onchange="applyFilters()">
    <option value="">Todos os Riscos</option>
    <option>CRITICO</option><option>ALTO</option><option>MEDIO</option><option>BAIXO</option><option>INFO</option>
  </select>
  <select id="f-status" onchange="applyFilters()">
    <option value="">Todos os Status</option>
    <option>NOVO</option><option>REINCIDENTE</option><option>CORRIGIDO</option><option>RESSURGIDO</option><option>RECONHECIDO</option>
  </select>
  <select id="f-mx" onchange="applyFilters()">
    <option value="">MX (todos)</option>
    <option value="sim">Com MX</option>
    <option value="nao">Sem MX</option>
  </select>
  <select id="f-whois" onchange="applyFilters()">
    <option value="">Registro (todos)</option>
    <option value="NOVO">Novo (&lt;30d)</option>
    <option value="RECENTE">Recente (&lt;1 ano)</option>
    <option value="ESTABELECIDO">Estabelecido</option>
    <option value="EXPIRANDO">Expirando</option>
    <option value="EXPIRADO">Expirado</option>
  </select>
  <select id="pgsize" aria-label="Itens por página" onchange="changePageSize()">
    <option value="50">50 por página</option><option value="100">100 por página</option>
    <option value="250">250 por página</option><option value="0">Todos</option>
  </select>
  <button class="btn btn-clr" onclick="clearFilters()">&#x2715; Limpar</button>
  <details class="colmenu no-print"><summary>&#x25A6; Colunas</summary><div class="colmenu-body" id="colmenu-body"></div></details>
</div>

<div class="tbl-wrap">
<table>
  <thead><tr>
    <th onclick="doSort('campanha')"    >Campanha     <span class="si" id="si-campanha"    >&#x21C5;</span></th>
    <th onclick="doSort('base_domain')" >Domínio-base <span class="si" id="si-base_domain" >&#x21C5;</span></th>
    <th onclick="doSort('domain')"      >Sósia        <span class="si" id="si-domain"      >&#x21C5;</span></th>
    <th onclick="doSort('fuzzer')"      >Técnica      <span class="si" id="si-fuzzer"      >&#x21C5;</span></th>
    <th onclick="doSort('ip')"          >IP           <span class="si" id="si-ip"          >&#x21C5;</span></th>
    <th onclick="doSort('mx')"          >MX           <span class="si" id="si-mx"          >&#x21C5;</span></th>
    <th onclick="doSort('whois_age_days')">Registro   <span class="si" id="si-whois_age_days">&#x21C5;</span></th>
    <th onclick="doSort('risk')"        >Risco        <span class="si" id="si-risk"        >&#x21C5;</span></th>
    <th onclick="doSort('status')"      >Status       <span class="si" id="si-status"      >&#x21C5;</span></th>
    <th onclick="doSort('ack_reason')"  >Motivo       <span class="si" id="si-ack_reason"  >&#x21C5;</span></th>
  </tr></thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<div id="no-results" class="no-results" style="display:none">Nenhum sósia para os filtros aplicados.</div>
<div class="pagination no-print" id="pagination"></div>

{footer}
</div><!-- /.wrap -->

<script>
{js_utils}
const DATA = {{all:{js_all},novo:{js_novo},rein:{js_rein},rem:{js_rem}}};
const CAMPANHAS = {campanhas_js};
const RISK_ORDER = {{'CRITICO':0,'ALTO':1,'MEDIO':2,'BAIXO':3,'INFO':4}};
let tab='all',filtered=[],sortKey='risk',sortAsc=true,page=1,pageSize=50;

function switchTab(t){{
  tab=t; ['all','novo','rein','rem'].forEach(x=>{{const e=document.getElementById('tab-'+x); if(e)e.classList.toggle('active',x===t);}});
  page=1; applyFilters();
}}
function initFilters(){{
  const sel=document.getElementById('f-camp');
  CAMPANHAS.forEach(c=>{{const o=document.createElement('option');o.value=c;o.textContent=c;sel.appendChild(o);}});
}}
function applyFilters(){{
  const q=(document.getElementById('q').value||'').toLowerCase().trim();
  const camp=document.getElementById('f-camp').value;
  const risk=document.getElementById('f-risk').value;
  const st=document.getElementById('f-status').value;
  const mx=document.getElementById('f-mx').value;
  const fw=document.getElementById('f-whois').value;
  filtered=DATA[tab].filter(x=>{{
    if(camp&&x.campanha!==camp)return false;
    if(risk&&x.risk!==risk)return false;
    if(st&&x.status!==st)return false;
    if(mx==='sim'&&!x.mx)return false;
    if(mx==='nao'&&x.mx)return false;
    if(fw&&(x.whois_status||'DESCONHECIDO')!==fw)return false;
    if(q){{const hay=(x.campanha+x.base_domain+x.domain+x.fuzzer+x.ip).toLowerCase();if(!hay.includes(q))return false;}}
    return true;
  }});
  page=1; applySort();
}}
function clearFilters(){{['q','f-camp','f-risk','f-status','f-mx','f-whois'].forEach(id=>{{const e=document.getElementById(id);if(e)e.value='';}});applyFilters();}}
function doSort(k){{
  if(sortKey===k)sortAsc=!sortAsc;else{{sortKey=k;sortAsc=true;}}
  document.querySelectorAll('.si').forEach(e=>e.textContent='\\u21C5');
  const si=document.getElementById('si-'+k);if(si)si.textContent=sortAsc?'\\u2191':'\\u2193';
  page=1;applySort();
}}
function applySort(){{
  filtered.sort((a,b)=>{{
    let va=_sortVal(a,sortKey),vb=_sortVal(b,sortKey);
    if(sortKey==='risk'){{va=RISK_ORDER[va]??9;vb=RISK_ORDER[vb]??9;return sortAsc?va-vb:vb-va;}}
    if(sortKey==='mx'){{return sortAsc?(a.mx?1:0)-(b.mx?1:0):(b.mx?1:0)-(a.mx?1:0);}}
    if(sortKey==='whois_age_days'){{const na=(a.whois_age_days<0?1e9:a.whois_age_days),nb=(b.whois_age_days<0?1e9:b.whois_age_days);return sortAsc?na-nb:nb-na;}}
    return sortAsc?String(va).localeCompare(String(vb)):String(vb).localeCompare(String(va));
  }});
  render();
}}
function changePageSize(){{pageSize=parseInt(document.getElementById('pgsize').value)||0;page=1;render();}}
function gotoPage(p){{
  const ps=pageSize||filtered.length||1,pages=Math.ceil(filtered.length/ps);
  page=Math.max(1,Math.min(p,pages));render();window.scrollTo({{top:0,behavior:'smooth'}});
}}
function render(){{
  const tbody=document.getElementById('tbody');
  const noRes=document.getElementById('no-results');
  const pgDiv=document.getElementById('pagination');
  const total=filtered.length;
  const ps=pageSize||total||1, pages=Math.ceil(total/ps);
  if(page>pages)page=pages;
  const start=(page-1)*ps,slice=filtered.slice(start,start+ps);
  noRes.style.display=total?'none':'block';
  let html='';
  slice.forEach(r=>{{
    const ackR=r.ack_reason||'';
    const mxc=r.mx?'<span class="ssl-bad">SIM</span>':'<span class="ssl-none">&#8212;</span>';
    const ws=r.whois_status||'DESCONHECIDO';
    const wage=(r.whois_age_days!=null&&r.whois_age_days>=0)?r.whois_age_days:null;
    const wtip=esc((r.whois_creation?('registrado em '+r.whois_creation):'data de registro desconhecida')+(wage!=null?(' · ~'+wage+' dia(s)'):''));
    let whoisCell;
    if(ws==='NOVO') whoisCell='<span class="whois-novo" title="'+wtip+'">NOVO</span>';
    else if(ws==='RECENTE') whoisCell='<span class="whois-recente" title="'+wtip+'">RECENTE</span>';
    else if(ws==='ESTABELECIDO') whoisCell='<span class="whois-estab" title="'+wtip+'">ESTABELECIDO</span>';
    else if(ws==='EXPIRANDO') whoisCell='<span class="whois-exp" title="'+wtip+'">EXPIRANDO</span>';
    else if(ws==='EXPIRADO') whoisCell='<span class="whois-expd" title="'+wtip+'">EXPIRADO</span>';
    else whoisCell='<span class="whois-unk">&#8212;</span>';
    html+=`<tr class="r-${{esc(r.risk)}}${{r.status==='RECONHECIDO'?' ack':''}}">
      <td><span class="camp-badge">${{esc(r.campanha)}}</span></td>
      <td><code>${{esc(r.base_domain)}}</code></td>
      <td><code>${{esc(r.domain)}}</code></td>
      <td>${{esc(r.fuzzer)}}</td>
      <td>${{esc(r.ip||'')}}</td>
      <td>${{mxc}}</td>
      <td>${{whoisCell}}</td>
      <td class="risk-${{esc(r.risk)}}">${{esc(r.risk)}}</td>
      <td><span class="status-${{esc(r.status)}}" title="${{esc(ackR)}}">${{esc(r.status)}}</span></td>
      <td>${{ackR?`<span class="ack-reason" title="${{esc(ackR)}}">${{esc(ackR)}}</span>`:''}}</td>
    </tr>`;
  }});
  tbody.innerHTML=html;
  renderPagination(pgDiv,page,pages,total,start,slice.length,'gotoPage');
}}
function exportCSV(){{
  const cols=['campanha','base_domain','domain','fuzzer','ip','mx','whois_status','whois_creation','whois_age_days','risk','status','ack_reason'];
  const rows=filtered.map(r=>cols.map(c=>'"'+String(r[c]!==undefined?r[c]:'').replace(/"/g,'""')+'"').join(','));
  const blob=new Blob([[cols.join(','),...rows].join('\\n')],{{type:'text/csv;charset=utf-8;'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='typosquat_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
}}
function rtExport(kind){{
  if(!kind) return;
  if(kind==='domains'){{ dl('dominios_sosia_'+_today()+'.txt', uniq(filtered.map(r=>r.domain)).join('\\n')); }}
  else if(kind==='json'){{ dl('typosquat_'+_today()+'.json', JSON.stringify(filtered,null,2), 'application/json'); }}
}}
function init(){{initFilters();applyFilters();}}
init();
</script>
</body>
</html>"""
    try:
        Path(output_path).write_text(html, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Falha ao gravar relatório HTML: {exc}") from exc


# ============================================================
# RELATÓRIO — GESTÃO DE ACHADOS (Findings, lido do argus.db)
# ============================================================

_SRC_LABEL = {"monitor": "Portas", "submonitor": "Subdomínios",
              "credentials": "Credenciais", "email": "E-mail", "typosquat": "Typosquat"}
_FST_OPTIONS = [("NOVO", "Novo"), ("EM_TRATAMENTO", "Em tratamento"),
                ("MITIGADO", "Mitigado"), ("FALSO_POSITIVO", "Falso Positivo")]


def _findings_rows_to_js(items: list[dict]) -> str:
    safe = []
    for r in items:
        safe.append({
            "id":           str(r.get("id", "")),
            "source":       str(r.get("source", "")),
            "category":     str(r.get("category", "")),
            "title":        str(r.get("title", "") or r.get("natural_key", "")),
            "severity":     str(r.get("severity", "INFO")),
            "status":       str(r.get("status", "NOVO")),
            "status_label": str(r.get("status_label", r.get("status", ""))),
            "active":       1 if r.get("active") else 0,
            "treated":      1 if r.get("treated") else 0,
            "campanha":     str(r.get("campanha", "") or ""),
            "notes":        int(r.get("notes", 0) or 0),
            "evidence":     int(r.get("evidence", 0) or 0),
            "first_seen":   str(r.get("first_seen", "") or ""),
            "last_seen":    str(r.get("last_seen", "") or ""),
        })
    return json.dumps(safe, ensure_ascii=False).replace("<", "\\u003c")


def _exec_findings(items: list[dict]) -> str:
    active = [r for r in items if r.get("active")]
    backlog = [r for r in active if not r.get("treated")]
    crit = sum(1 for r in backlog if r.get("severity") == "CRITICO")
    alto = sum(1 for r in backlog if r.get("severity") == "ALTO")
    mitig = sum(1 for r in items if r.get("status") == "MITIGADO")
    fp = sum(1 for r in items if r.get("status") == "FALSO_POSITIVO")
    lead = (f"{len(items)} achado(s) no total, {len(active)} ativo(s). "
            f"<b>Backlog de {len(backlog)} não tratado(s)</b>"
            + (f" — <b>{crit} crítico(s)</b> e {alto} de alto risco exigem ação."
               if (crit or alto) else " sem críticos pendentes.")
            + f" Tratados: {mitig} mitigado(s), {fp} falso(s)-positivo(s).")
    backlog.sort(key=lambda r: _SEV_RANK.get(r.get("severity"), 5))
    risks = []
    for r in backlog[:5]:
        sv = r.get("severity")
        if sv not in ("CRITICO", "ALTO", "MEDIO"):
            continue
        src = _SRC_LABEL.get(r.get("source"), r.get("source"))
        risks.append(f'<span class="sv risk-{sv}">{sv}</span> [{_h(src)}] {_h(r.get("title"))}')
    recs = []
    def add(c):
        if c not in recs: recs.append(c)
    if crit: add("Priorize a triagem dos achados <b>críticos</b> do backlog (Em tratamento → Mitigado) e registre as tratativas.")
    if any(not r.get("treated") and r.get("notes", 0) == 0 for r in backlog):
        add("Há achados sem nota/tratativa — documente análise e decisão (rastreabilidade ISO 27001/CIS).")
    if fp: add("Revise periodicamente os Falsos Positivos para evitar mascarar exposições reais.")
    add("Use <code>argus-finding</code> para mudar status, anexar notas e evidências (auditado).")
    return _exec_panel(lead, risks, recs)


_FST_COLOR = {"NOVO": "#7dd3fc", "EM_TRATAMENTO": "#fcd34d",
              "MITIGADO": "#6ee7b7", "FALSO_POSITIVO": "#8a99b4"}
_AGING_COLOR = {"<7d": "var(--green)", "7-30d": "var(--yellow)", "30-90d": "var(--orange)", ">90d": "var(--red)"}


def _trend_svg(trends: list) -> str:
    if not trends or not any((t.get("new") or t.get("treated")) for t in trends):
        return '<p class="empty">Sem histórico suficiente para tendência ainda.</p>'
    # Quando só uma ou duas semanas têm dados, o gráfico parece "vazio" — explica que
    # o histórico se preenche conforme as execuções, indicando desde quando há dados.
    weeks_with_data = sum(1 for t in trends if (t.get("new") or t.get("treated")))
    _since = next((t.get("label", "") for t in trends if (t.get("new") or t.get("treated"))), "")
    sparse_note = (
        f'<p class="empty" style="margin-top:6px">Histórico em formação{f" — dados desde {_since}" if _since else ""}; '
        'as semanas anteriores preenchem conforme as próximas execuções.</p>'
    ) if weeks_with_data <= 2 else ''
    W, H, pad = 560, 140, 26
    n = len(trends); maxv = max([max(t["new"], t["treated"]) for t in trends] + [1])
    bw = (W - 2 * pad) / n
    out = [f'<line x1="{pad}" y1="{H-22}" x2="{W-pad}" y2="{H-22}" stroke="var(--border)" stroke-width="1"/>']
    for i, t in enumerate(trends):
        x = pad + i * bw
        hn = (t["new"] / maxv) * (H - 44); ht = (t["treated"] / maxv) * (H - 44)
        w2 = bw * 0.30
        out.append(f'<rect x="{x+bw*0.16:.1f}" y="{H-22-hn:.1f}" width="{w2:.1f}" height="{hn:.1f}" fill="#33a3ef" rx="2"><title>{t["new"]} novo(s)</title></rect>')
        out.append(f'<rect x="{x+bw*0.52:.1f}" y="{H-22-ht:.1f}" width="{w2:.1f}" height="{ht:.1f}" fill="#34d399" rx="2"><title>{t["treated"]} tratado(s)</title></rect>')
        out.append(f'<text x="{x+bw/2:.1f}" y="{H-7}" text-anchor="middle" font-size="9" fill="var(--faint)">{t["label"]}</text>')
    return f'<svg viewBox="0 0 {W} {H}" width="100%" style="max-width:100%">{"".join(out)}</svg>{sparse_note}'


def _bar_rows(d: dict, labelmap=None, colormap=None) -> str:
    if not d:
        return '<div class="empty">—</div>'
    tot = sum(d.values()) or 1
    rows = ""
    for k, v in sorted(d.items(), key=lambda kv: -kv[1]):
        label = (labelmap or {}).get(k, k)
        color = (colormap or {}).get(k, "var(--accent)")
        pct = v / tot * 100
        rows += ('<div class="legend-item" style="width:100%">'
                 f'<span style="min-width:130px">{_h(label)}</span>'
                 f'<div class="sbar" style="flex:1;margin:0 8px;height:8px"><i style="background:{color};width:{pct:.0f}%"></i></div>'
                 f'<b>{v}</b></div>')
    return rows


def _findings_stats_panel(stats: dict) -> str:
    if not stats:
        return ""
    mttt = "—" if stats.get("mttt_days") is None else f'{stats["mttt_days"]} d'
    kpi = (
        '<div class="kpi-grid" style="margin-bottom:14px">'
        f'<div class="kpi sev-alto"><div class="v">{stats.get("backlog",0)}</div><div class="l">Backlog</div></div>'
        f'<div class="kpi"><div class="v">{stats.get("treated",0)}</div><div class="l">Tratados</div></div>'
        f'<div class="kpi"><div class="v">{mttt}</div><div class="l">Tempo médio p/ tratar</div></div>'
        f'<div class="kpi sev-crit"><div class="v">{stats.get("oldest_days",0)} d</div><div class="l">Achado mais antigo</div></div>'
        '</div>'
    )
    src_labels = {k: _SRC_LABEL.get(k, k) for k in stats.get("by_source", {})}
    fst_labels = dict(_FST_OPTIONS)
    left = (
        '<div>'
        '<h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin-bottom:8px">'
        'Tendência (8 semanas) &middot; <span style="color:#33a3ef">novos</span> &times; <span style="color:#34d399">tratados</span></h3>'
        f'{_trend_svg(stats.get("trends", []))}'
        '<h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin:14px 0 8px">Backlog por idade (aging)</h3>'
        f'<div class="legend" style="flex-direction:column;gap:7px">{_bar_rows(stats.get("aging", {}), colormap=_AGING_COLOR)}</div>'
        '</div>'
    )
    right = (
        '<div>'
        '<h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin-bottom:8px">Por status</h3>'
        f'<div class="legend" style="flex-direction:column;gap:7px">{_bar_rows(stats.get("by_status", {}), labelmap=fst_labels, colormap=_FST_COLOR)}</div>'
        '<h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin:14px 0 8px">Por fonte (módulo)</h3>'
        f'<div class="legend" style="flex-direction:column;gap:7px">{_bar_rows(stats.get("by_source", {}), labelmap=src_labels)}</div>'
        '</div>'
    )
    return ('<div class="panel panel-pad"><h2>&#x1F4C8; Estatísticas &amp; Tendências</h2>'
            + kpi + '<div class="grid-2">' + left + right + '</div></div>')


def generate_findings_report(snapshot: dict, output_path: str = "findings_report.html",
                             threatintel_available: bool = False, stats: dict | None = None) -> None:
    """Página de Gestão de Achados (read-only) renderizada a partir do snapshot do
    domínio (argus.db). Surfaça status/severidade/histórico-resumido na Web,
    mantendo a arquitetura estática atual. As AÇÕES (mudar status etc.) ficam para
    a Fase 2.1 (backend); aqui, a triagem é via `argus-finding`."""
    now   = snapshot.get("generated_at") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    items = snapshot.get("findings", [])
    active  = [r for r in items if r.get("active")]
    treated = [r for r in items if r.get("treated")]
    backlog = [r for r in active if not r.get("treated")]

    js_all  = _findings_rows_to_js(items)
    js_back = _findings_rows_to_js(backlog)
    js_trt  = _findings_rows_to_js(treated)

    total_crit = sum(1 for r in backlog if r.get("severity") == "CRITICO")
    total_alto = sum(1 for r in backlog if r.get("severity") == "ALTO")
    mitig  = sum(1 for r in items if r.get("status") == "MITIGADO")
    fp     = sum(1 for r in items if r.get("status") == "FALSO_POSITIVO")
    sev_counts = {s: sum(1 for r in active if r.get("severity") == s)
                  for s in ("CRITICO", "ALTO", "MEDIO", "BAIXO", "INFO")}
    st_counts = {st: sum(1 for r in items if r.get("status") == st) for st, _ in _FST_OPTIONS}
    campanhas_js = json.dumps(
        sorted({r.get("campanha", "") for r in items if r.get("campanha")}),
        ensure_ascii=False).replace("<", "\\u003c")
    controls_js = json.dumps(snapshot.get("controls", {}), ensure_ascii=False).replace("<", "\\u003c")

    css = _common_css(); js_utils = _common_js_utils()
    topbar = _topbar("findings"); footer = _footer()
    kpis = _kpi_tiles([
        (len(items),   "Achados",        "",                            "k-total"),
        (len(active),  "Ativos",         "",                            "k-active"),
        (len(backlog), "Backlog",        "sev-alto" if backlog else "", "k-backlog"),
        (total_crit,   "Críticos (backlog)", "sev-crit",                "k-crit"),
        (mitig,        "Mitigado",       "",                            "k-mitig"),
        (fp,           "Falso Positivo", "",                            "k-fp"),
    ])
    donut = _donut(sev_counts, "Ativos por severidade")
    exec_panel = _exec_findings(items)
    stats_panel = _findings_stats_panel(stats)
    status_opts = "".join(f'<option value="{st}">{lb}</option>' for st, lb in _FST_OPTIONS)
    kpi_json = json.dumps({
        "scope": "findings", "now": now,
        "total": len(items), "active": len(active), "backlog": len(backlog),
        "critico": total_crit, "alto": total_alto, "mitig": mitig, "fp": fp,
        "by_status": st_counts,
        "campanhas": sorted({r.get("campanha", "") for r in items if r.get("campanha")}),
    }, ensure_ascii=False).replace("<", "\\u003c")

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Argus · Gestão de Achados</title>
<link rel="icon" type="image/svg+xml" href="{_FAVICON}">
<style>{css}</style>
<style>
  .act-wrap {{ display:flex; gap:5px; align-items:center; }}
  .act-sel {{ background:var(--surface); border:1px solid var(--border); color:var(--text);
              border-radius:6px; font-size:11px; padding:3px 5px; cursor:pointer; }}
  .act-btn {{ background:var(--surface); border:1px solid var(--border); color:var(--muted);
              border-radius:6px; padding:3px 7px; cursor:pointer; font-size:12px; }}
  .act-btn:hover {{ color:var(--accent); border-color:var(--accent); }}
  #toast {{ position:fixed; right:18px; bottom:18px; z-index:999; padding:11px 16px; border-radius:10px;
            font-size:13px; font-weight:600; box-shadow:var(--shadow); display:none; }}
  #toast.ok  {{ background:rgba(52,211,153,.16); color:#a7f3d0; border:1px solid rgba(52,211,153,.4); }}
  #toast.err {{ background:rgba(244,63,94,.16); color:#fda4af; border:1px solid rgba(244,63,94,.4); }}
  .fid-link {{ cursor:pointer; color:var(--accent); text-decoration:underline dotted; }}
  .modal {{ position:fixed; inset:0; background:rgba(3,6,12,.66); z-index:1000; display:none;
            align-items:flex-start; justify-content:center; padding:40px 16px; overflow:auto; }}
  .modal.open {{ display:flex; }}
  .modal-card {{ position:relative; background:var(--surface-2); border:1px solid var(--border);
                 border-radius:14px; max-width:780px; width:100%; box-shadow:var(--shadow); padding:22px 24px; }}
  .modal-close {{ position:absolute; top:14px; right:16px; cursor:pointer; background:var(--surface);
                  border:1px solid var(--border); border-radius:8px; color:var(--muted); padding:2px 11px; font-size:18px; line-height:1.4; }}
  .modal-card h3 {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.7px; margin:16px 0 6px; }}
  .modal-card pre {{ background:var(--surface); border:1px solid var(--border); border-radius:8px;
                     padding:10px; font-size:11.5px; color:var(--muted); overflow:auto; white-space:pre-wrap; }}
  .tl {{ list-style:none; margin:6px 0 0; padding:0; border-left:2px solid var(--border); }}
  .tl li {{ position:relative; padding:6px 0 6px 16px; font-size:12.5px; color:var(--muted); }}
  .tl li::before {{ content:''; position:absolute; left:-5px; top:11px; width:8px; height:8px; border-radius:50%; background:var(--accent); }}
  .ml-row {{ font-size:12.5px; color:var(--text); padding:4px 0; border-bottom:1px solid rgba(35,49,76,.5); }}
</style>
</head>
<body>
{topbar}
<script id="exm-kpis" type="application/json">{kpi_json}</script>
<div class="wrap" id="conteudo" role="main">

<div class="page-head">
  <div>
    <h1 class="page-title">Gestão de Achados <span class="chip">ISO 27001 · CIS · rastreável</span></h1>
    <div class="page-sub">Ciclo de vida dos achados (status, tratativas, evidências) &middot; atualizado em: {now}</div>
  </div>
  <div class="actions no-print">
    <button class="btn btn-pdf" onclick="exportPDF()">Exportar PDF</button>
    <button class="btn btn-csv" onclick="exportCSV()">Exportar CSV</button>
  </div>
</div>

<div class="summary">
  {kpis}
  {donut}
</div>

{exec_panel}

{stats_panel}

<div class="tabs no-print">
  <div class="tab active" onclick="switchTab('backlog')" id="tab-backlog">Backlog      <span class="badge" id="b-backlog">{len(backlog)}</span></div>
  <div class="tab"        onclick="switchTab('treated')" id="tab-treated">Tratados     <span class="badge" id="b-treated">{len(treated)}</span></div>
  <div class="tab"        onclick="switchTab('all')"     id="tab-all"    >Todos        <span class="badge" id="b-all">{len(items)}</span></div>
</div>

<div class="toolbar no-print">
  <input type="text" id="q" aria-label="Buscar achados" placeholder="&#x1F50D;  Busca (achado, categoria, campanha, id...)" oninput="applyFilters()">
  <select id="f-source" aria-label="Filtrar por fonte" onchange="applyFilters()">
    <option value="">Todas as Fontes</option>
    <option value="monitor">Portas</option><option value="submonitor">Subdomínios</option>
    <option value="credentials">Credenciais</option><option value="email">E-mail</option><option value="typosquat">Typosquat</option>
  </select>
  <select id="f-sev" aria-label="Filtrar por severidade" onchange="applyFilters()">
    <option value="">Todas as Severidades</option>
    <option>CRITICO</option><option>ALTO</option><option>MEDIO</option><option>BAIXO</option><option>INFO</option>
  </select>
  <select id="f-status" aria-label="Filtrar por estado" onchange="applyFilters()">
    <option value="">Todos os Estados</option>
    {status_opts}
  </select>
  <select id="f-active" aria-label="Filtrar por observação" onchange="applyFilters()">
    <option value="">Observação (todas)</option>
    <option value="1">Ativo (observado)</option>
    <option value="0">Não observado</option>
  </select>
  <select id="f-camp" aria-label="Filtrar por campanha" onchange="applyFilters()"><option value="">Todas as Campanhas</option></select>
  <select id="pgsize" aria-label="Itens por página" onchange="changePageSize()">
    <option value="50">50 por página</option><option value="100">100 por página</option>
    <option value="250">250 por página</option><option value="0">Todos</option>
  </select>
  <button class="btn btn-clr" onclick="clearFilters()">&#x2715; Limpar</button>
  <details class="colmenu no-print"><summary>&#x25A6; Colunas</summary><div class="colmenu-body" id="colmenu-body"></div></details>
</div>

<div class="tbl-wrap">
<table>
  <thead><tr>
    <th onclick="doSort('id')"        >ID         <span class="si" id="si-id"        >&#x21C5;</span></th>
    <th onclick="doSort('source')"    >Fonte      <span class="si" id="si-source"    >&#x21C5;</span></th>
    <th onclick="doSort('category')"  >Categoria  <span class="si" id="si-category"  >&#x21C5;</span></th>
    <th onclick="doSort('severity')"  >Severidade <span class="si" id="si-severity"  >&#x21C5;</span></th>
    <th onclick="doSort('status')"    >Estado     <span class="si" id="si-status"    >&#x21C5;</span></th>
    <th onclick="doSort('active')"    >Obs.       <span class="si" id="si-active"    >&#x21C5;</span></th>
    <th onclick="doSort('campanha')"  >Campanha   <span class="si" id="si-campanha"  >&#x21C5;</span></th>
    <th>Notas/Evid</th>
    <th onclick="doSort('first_seen')">1ª obs.    <span class="si" id="si-first_seen">&#x21C5;</span></th>
    <th onclick="doSort('last_seen')" >Últ. obs.  <span class="si" id="si-last_seen" >&#x21C5;</span></th>
    <th onclick="doSort('title')"     >Achado     <span class="si" id="si-title"     >&#x21C5;</span></th>
    <th class="no-print">Ações</th>
  </tr></thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<div id="no-results" class="no-results" style="display:none">Nenhum achado para os filtros aplicados.</div>
<div class="pagination no-print" id="pagination"></div>

<p class="page-sub no-print" style="margin-top:12px">
  Triagem (auditada): <code>argus-finding set &lt;id&gt; em-tratamento|mitigado|fp --note "..."</code>
  · <code>argus-finding note &lt;id&gt; "..."</code> · <code>argus-finding evidence &lt;id&gt; "rótulo" "ref"</code>
  &middot; ou use os controles da coluna <b>Ações</b> (requer o serviço web ativo).
</p>

<div id="toast"></div>
<div id="detail" class="modal" onclick="if(event.target===this)closeDetail()">
  <div class="modal-card">
    <button class="modal-close" onclick="closeDetail()" title="Fechar">&times;</button>
    <div id="detail-body"></div>
  </div>
</div>
{footer}
</div><!-- /.wrap -->

<script>
{js_utils}
const SRC_LABEL = {{monitor:'Portas',submonitor:'Subdomínios',credentials:'Credenciais',email:'E-mail',typosquat:'Typosquat'}};
const CONTROLS = {controls_js};
function fstBadge(st,label){{
  const m={{NOVO:'#7dd3fc',EM_TRATAMENTO:'#fcd34d',MITIGADO:'#6ee7b7',FALSO_POSITIVO:'#8a99b4'}};
  const c=m[st]||'#8a99b4';
  return '<span style="color:'+c+';background:'+c+'22;font-weight:700;font-size:11px;border:1px solid '+c+'80;border-radius:6px;padding:2px 8px;white-space:nowrap">'+esc(label||st)+'</span>';
}}
const DATA = {{all:{js_all},backlog:{js_back},treated:{js_trt}}};
const CAMPANHAS = {campanhas_js};
const RISK_ORDER = {{'CRITICO':0,'ALTO':1,'MEDIO':2,'BAIXO':3,'INFO':4}};
let tab='backlog',filtered=[],sortKey='severity',sortAsc=true,page=1,pageSize=50;

function switchTab(t){{
  tab=t; ['backlog','treated','all'].forEach(x=>{{
    const e=document.getElementById('tab-'+x); if(e)e.classList.toggle('active',x===t);
  }}); page=1; applyFilters();
}}
function initFilters(){{
  const sel=document.getElementById('f-camp');
  CAMPANHAS.forEach(c=>{{const o=document.createElement('option');o.value=c;o.textContent=c;sel.appendChild(o);}});
}}
function applyFilters(){{
  const q=(document.getElementById('q').value||'').toLowerCase().trim();
  const src=document.getElementById('f-source').value;
  const sev=document.getElementById('f-sev').value;
  const st=document.getElementById('f-status').value;
  const ac=document.getElementById('f-active').value;
  const camp=document.getElementById('f-camp').value;
  filtered=DATA[tab].filter(x=>{{
    if(src&&x.source!==src)return false;
    if(sev&&x.severity!==sev)return false;
    if(st&&x.status!==st)return false;
    if(ac!==''&&String(x.active)!==ac)return false;
    if(camp&&x.campanha!==camp)return false;
    if(q){{const hay=(x.id+x.title+x.category+x.campanha+x.source).toLowerCase();if(!hay.includes(q))return false;}}
    return true;
  }});
  page=1; applySort();
}}
function clearFilters(){{['q','f-source','f-sev','f-status','f-active','f-camp'].forEach(id=>{{const e=document.getElementById(id);if(e)e.value='';}});applyFilters();}}
function doSort(k){{
  if(sortKey===k)sortAsc=!sortAsc;else{{sortKey=k;sortAsc=true;}}
  document.querySelectorAll('.si').forEach(e=>e.textContent='\\u21C5');
  const si=document.getElementById('si-'+k);if(si)si.textContent=sortAsc?'\\u2191':'\\u2193';
  page=1;applySort();
}}
function applySort(){{
  filtered.sort((a,b)=>{{
    let va=_sortVal(a,sortKey),vb=_sortVal(b,sortKey);
    if(sortKey==='severity'){{va=RISK_ORDER[va]??9;vb=RISK_ORDER[vb]??9;return sortAsc?va-vb:vb-va;}}
    if(['active','notes','evidence'].includes(sortKey))return sortAsc?Number(va)-Number(vb):Number(vb)-Number(va);
    return sortAsc?String(va).localeCompare(String(vb)):String(vb).localeCompare(String(va));
  }});
  render();
}}
function changePageSize(){{pageSize=parseInt(document.getElementById('pgsize').value)||0;page=1;render();}}
function gotoPage(p){{
  const ps=pageSize||filtered.length||1,pages=Math.ceil(filtered.length/ps);
  page=Math.max(1,Math.min(p,pages));render();window.scrollTo({{top:0,behavior:'smooth'}});
}}
function render(){{
  const tbody=document.getElementById('tbody');
  const noRes=document.getElementById('no-results');
  const pgDiv=document.getElementById('pagination');
  const total=filtered.length;
  const ps=pageSize||total||1, pages=Math.ceil(total/ps);
  if(page>pages)page=pages;
  const start=(page-1)*ps,slice=filtered.slice(start,start+ps);
  noRes.style.display=total?'none':'block';
  let html='';
  slice.forEach(r=>{{
    const act=r.active?'<span class="dnssec-on">ativo</span>':'<span class="whois-unk">&#8212;</span>';
    const ne=(r.notes||r.evidence)?`<span class="badge">${{r.notes}}N · ${{r.evidence}}E</span>`:'<span class="ssl-none">&#8212;</span>';
    html+=`<tr class="r-${{esc(r.severity)}}">
      <td><code class="fid-link" title="ver detalhe e histórico" onclick="openDetail('${{esc(r.id)}}')">${{esc(r.id.slice(0,10))}}</code></td>
      <td>${{esc(SRC_LABEL[r.source]||r.source)}}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{esc(r.category)}}">${{esc(r.category)}}</td>
      <td class="risk-${{esc(r.severity)}}">${{esc(r.severity)}}</td>
      <td>${{fstBadge(r.status,r.status_label)}}</td>
      <td>${{act}}</td>
      <td>${{r.campanha?`<span class="camp-badge">${{esc(r.campanha)}}</span>`:''}}</td>
      <td>${{ne}}</td>
      <td>${{esc((r.first_seen||'').slice(0,10))}}</td>
      <td>${{esc((r.last_seen||'').slice(0,10))}}</td>
      <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{esc(r.title)}}">${{esc(r.title)}}</td>
      <td class="no-print"><div class="act-wrap">${{statusSelect(r.id,r.status)}}<button class="act-btn" title="Adicionar nota/tratativa" onclick="addNoteUI('${{esc(r.id)}}')">&#x1F4DD;</button><button class="act-btn" title="Adicionar evidência" onclick="addEvidUI('${{esc(r.id)}}')">&#x1F4CE;</button></div></td>
    </tr>`;
  }});
  tbody.innerHTML=html;
  renderPagination(pgDiv,page,pages,total,start,slice.length,'gotoPage');
}}
const FST=[['NOVO','Novo'],['EM_TRATAMENTO','Em tratamento'],['MITIGADO','Mitigado'],['FALSO_POSITIVO','Falso Positivo']];
const _TREATED=['EM_TRATAMENTO','MITIGADO','FALSO_POSITIVO'];
function statusSelect(id,cur){{
  const o=FST.map(s=>'<option value="'+s[0]+'"'+(s[0]===cur?' selected':'')+'>'+s[1]+'</option>').join('');
  return '<select class="act-sel" title="Alterar estado do achado" onchange="setStatus(\\''+id+'\\',this.value)">'+o+'</select>';
}}
let _toastT;
function _toast(msg,ok){{
  const e=document.getElementById('toast'); if(!e) return;
  e.textContent=msg; e.className=ok?'ok':'err'; e.style.display='block';
  clearTimeout(_toastT); _toastT=setTimeout(()=>{{e.style.display='none';}},2800);
}}
async function apiPost(path,body){{
  try{{
    const r=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json','X-Requested-With':'argus'}},body:JSON.stringify(body||{{}})}});
    let j={{}}; try{{ j=await r.json(); }}catch(e){{}}
    return {{ok:r.ok&&j.ok, code:r.status, j}};
  }}catch(e){{ return {{ok:false, code:0, j:{{error:'serviço indisponível'}}}}; }}
}}
function _rebucket(){{
  // Reconstrói backlog/tratados a partir de DATA.all (fonte da verdade), para um
  // item tratado sair do backlog e entrar em "Tratados" sem precisar recarregar.
  DATA.backlog=DATA.all.filter(x=>x.active&&!x.treated);
  DATA.treated=DATA.all.filter(x=>x.treated);
}}
function updateTabCounts(){{
  const set=(id,n)=>{{const e=document.getElementById(id); if(e)e.textContent=n;}};
  // badges das abas
  set('b-backlog',DATA.backlog.length); set('b-treated',DATA.treated.length); set('b-all',DATA.all.length);
  // KPIs do topo (mesma fonte: DATA) — mantêm consistência ao tratar/hidratar
  set('k-total',DATA.all.length);
  set('k-active',DATA.all.filter(x=>x.active).length);
  set('k-backlog',DATA.backlog.length);
  set('k-crit',DATA.backlog.filter(x=>x.severity==='CRITICO').length);
  set('k-mitig',DATA.all.filter(x=>x.status==='MITIGADO').length);
  set('k-fp',DATA.all.filter(x=>x.status==='FALSO_POSITIVO').length);
}}
function _patch(id,fn){{ DATA.all.forEach(x=>{{ if(x.id===id) fn(x); }}); _rebucket(); updateTabCounts(); applyFilters(); }}
async function setStatus(id,status){{
  if(!status) return;
  const res=await apiPost('/api/findings/'+id+'/status',{{status}});
  if(res.ok){{ _toast('Status atualizado: '+(res.j.status_label||status),true);
    _patch(id,x=>{{x.status=res.j.status; x.status_label=res.j.status_label; x.treated=_TREATED.includes(res.j.status)?1:0;}}); }}
  else _toast('Falha: '+((res.j&&res.j.error)||res.code),false);
}}
async function addNoteUI(id){{
  const n=prompt('Nota / tratativa (auditada):'); if(!n) return;
  const res=await apiPost('/api/findings/'+id+'/note',{{note:n}});
  if(res.ok){{ _toast('Nota adicionada',true); _patch(id,x=>{{x.notes=(x.notes||0)+1;}}); }}
  else _toast('Falha: '+((res.j&&res.j.error)||res.code),false);
}}
async function addEvidUI(id){{
  const label=prompt('Rótulo da evidência (ex.: print, log, scan):'); if(!label) return;
  const ref=prompt('Referência (caminho, URL ou hash):'); if(!ref) return;
  const res=await apiPost('/api/findings/'+id+'/evidence',{{label,ref}});
  if(res.ok){{ _toast('Evidência adicionada',true); _patch(id,x=>{{x.evidence=(x.evidence||0)+1;}}); }}
  else _toast('Falha: '+((res.j&&res.j.error)||res.code),false);
}}
const _FSTLBL=Object.fromEntries(FST);
async function apiGet(path){{
  try{{ const r=await fetch(path,{{headers:{{'X-Requested-With':'argus'}}}}); let j={{}}; try{{j=await r.json();}}catch(e){{}} return {{ok:r.ok&&j.ok,code:r.status,j}}; }}
  catch(e){{ return {{ok:false,code:0,j:{{error:'serviço indisponível'}}}}; }}
}}
function closeDetail(){{ const m=document.getElementById('detail'); if(m) m.classList.remove('open'); }}
document.addEventListener('keydown',e=>{{ if(e.key==='Escape') closeDetail(); }});
async function openDetail(id){{
  const m=document.getElementById('detail'), b=document.getElementById('detail-body');
  if(!m||!b) return;
  b.innerHTML='<p class="empty">Carregando&hellip;</p>'; m.classList.add('open');
  const res=await apiGet('/api/findings/'+id);
  if(!res.ok){{ b.innerHTML='<p class="empty">Detalhe indisponível (serviço web inativo). No terminal: <code>argus-finding show '+esc(id.slice(0,10))+'</code></p>'; return; }}
  const f=res.j.finding;
  let h='<h2 style="margin-bottom:3px">'+esc(f.title||f.natural_key)+'</h2>';
  h+='<div class="page-sub" style="margin-bottom:12px">'+esc(SRC_LABEL[f.source]||f.source)+' &middot; '+esc(f.category||'')+' &middot; <code>'+esc(f.id)+'</code></div>';
  h+='<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px">';
  h+='<span class="risk-'+esc(f.severity)+'" style="font-weight:800">'+esc(f.severity)+'</span>';
  h+=fstBadge(f.status,_FSTLBL[f.status]||f.status);
  h+=(f.active?'<span class="dnssec-on">ativo</span>':'<span class="whois-unk">não observado</span>')+'</div>';
  h+='<div class="page-sub">1ª obs.: '+esc(f.first_seen||'—')+' &middot; Últ. obs.: '+esc(f.last_seen||'—')+' &middot; Campanha: '+esc(f.campanha||'—')+'</div>';
  if(f.details && Object.keys(f.details).length) h+='<h3>Detalhes técnicos</h3><pre>'+esc(JSON.stringify(f.details,null,1))+'</pre>';
  if((f.notes_l||[]).length){{ h+='<h3>Notas / tratativas</h3>'; f.notes_l.forEach(n=>{{ h+='<div class="ml-row"><b>'+esc(n.actor)+'</b> <span class="page-sub">'+esc(n.ts)+'</span><br>'+esc(n.note)+'</div>'; }}); }}
  if((f.evidence_l||[]).length){{ h+='<h3>Evidências</h3>'; f.evidence_l.forEach(e=>{{ h+='<div class="ml-row"><b>'+esc(e.label)+'</b>: '+esc(e.ref)+' <span class="page-sub">('+esc(e.actor)+', '+esc(e.ts)+')</span></div>'; }}); }}
  const ctrl=f.controls||CONTROLS[f.source]||{{}};
  if(ctrl && ((ctrl.iso||[]).length||(ctrl.cis||[]).length||(ctrl.pci||[]).length)){{
    const fmt=(arr,lbl)=>(arr&&arr.length)?('<div class="ml-row"><b>'+lbl+'</b>: '+arr.map(esc).join(' &middot; ')+'</div>'):'';
    h+='<h3>Controles relacionados (conformidade)</h3>'+fmt(ctrl.iso,'ISO 27002')+fmt(ctrl.cis,'CIS v8')+fmt(ctrl.pci,'PCI-DSS');
  }}
  h+='<h3>Histórico (auditoria)</h3><ul class="tl">';
  (f.history||[]).forEach(ev=>{{ let line=esc(ev.action); if(ev.to_status) line+=' '+esc(ev.from_status||'?')+' &rarr; '+esc(ev.to_status); if(ev.note) line+=' &middot; '+esc(ev.note); h+='<li><b>'+esc(ev.ts)+'</b> &middot; '+esc(ev.actor)+' &middot; '+line+'</li>'; }});
  h+='</ul>';
  b.innerHTML=h;
}}
function exportCSV(){{
  const cols=['id','source','category','severity','status','status_label','active','campanha','notes','evidence','first_seen','last_seen','title'];
  const rows=filtered.map(r=>cols.map(c=>'"'+String(r[c]!==undefined?r[c]:'').replace(/"/g,'""')+'"').join(','));
  const blob=new Blob([[cols.join(','),...rows].join('\\n')],{{type:'text/csv;charset=utf-8;'}});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='findings_'+new Date().toISOString().slice(0,10)+'.csv';a.click();
  _toast('CSV exportado: '+rows.length+' linha(s)',true);
}}
function exportPDF(){{ _toast('Abrindo diálogo de impressão/PDF…',true); setTimeout(function(){{window.print();}},120); }}
async function hydrate(){{
  // Ao carregar, busca os achados frescos do banco via API (se o serviço estiver
  // no ar) — assim a página SEMPRE reflete o estado real, mesmo que a regeneração
  // do HTML estático tenha falhado. Se o serviço estiver off, mantém o estático.
  try{{
    const r=await fetch('/api/findings',{{headers:{{'X-Requested-With':'argus'}}}});
    if(!r.ok) return; const j=await r.json();
    if(!j||!Array.isArray(j.findings)) return;
    DATA.all=j.findings; _rebucket(); updateTabCounts(); applyFilters();
  }}catch(e){{}}
}}
function init(){{initFilters();updateTabCounts();applyFilters();hydrate();}}
init();
</script>
</body>
</html>"""

    try:
        Path(output_path).write_text(html, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Falha ao gravar relatório HTML: {exc}") from exc


def write_findings_page(docroot: str = "/var/www/argus", db_path: str | None = None,
                        local_name: str = "findings_report.html") -> str | None:
    """Conveniência para os scanners: lê o snapshot do domínio (argus.db) e
    gera a página de Gestão de Achados no docroot (e cópia local). Import de
    `findings` é tardio (presentation→domain, sem ciclo). Nunca levanta."""
    try:
        import findings as _fmod
    except Exception:
        return None
    try:
        snap = _fmod.snapshot(db_path)
        try: stt = _fmod.stats(db_path)
        except Exception: stt = None
    except Exception:
        return None
    import os as _os
    import shutil as _sh
    from pathlib import Path as _P
    droot = _P(docroot)
    out = str(droot / local_name) if droot.exists() else local_name
    try:
        generate_findings_report(snap, output_path=out, stats=stt)
        _os.chmod(out, 0o644)
        if out != local_name:
            try: _sh.copy2(out, local_name)
            except Exception: pass
        return out
    except Exception:
        return None


def build_index() -> str:
    cards = [
        ("dashboard",  "/dashboard.html",         "Dashboard",
         "Visão consolidada: KPIs de severidade, campanhas e agenda dos scans."),
        ("findings",   "/findings_report.html",   "Gestão de Achados",
         "Ciclo de vida dos achados: status, triagem, tratativas e evidências (auditado)."),
        ("monitor",    "/monitor_report.html",    "Monitor de Portas",
         "Superfície exposta — IPs e portas abertas, com risco e reputação AbuseIPDB."),
        ("submonitor", "/submonitor_report.html", "Monitor de Subdomínios",
         "Subdomínios ativos, IP/ASN, SSL, urlscan.io e RDAP/WHOIS."),
        ("credentials","/credentials_report.html","Exposição de Credenciais",
         "Exposição de credenciais em logs de infostealer (Hudson Rock)."),
        ("email",      "/email_report.html",      "Postura de E-mail",
         "Anti-spoofing por domínio — SPF, DMARC e DKIM (autenticação de e-mail)."),
        ("typosquat",  "/typosquat_report.html",  "Typosquat",
         "Domínios sósia registrados (typosquatting/homoglyph, dnstwist) — risco de phishing."),
        ("risk",       "/risk-guide.html",        "Guia de Risco",
         "Como o risco é calculado em cada camada do Risk Engine."),
    ]
    hub = '<div class="hub-grid">' + "".join(
        f'<a class="hub-card" href="{href}"><div class="ic">{_NAV_ICONS[key]}</div>'
        f'<div><h3>{title}</h3><p>{desc}</p></div></a>'
        for key, href, title, desc in cards
    ) + '</div>'
    pillars = [("Discover", "discover"), ("Enumerate", "enumerate"),
               ("Assess", "assess"), ("Prioritize", "prioritize")]
    pillars_html = '<div class="pillars">' + "".join(
        f'<div class="pillar">{_PILLAR_ICONS[k]}<span>{label}</span></div>'
        for label, k in pillars
    ) + '</div>'
    hero = (
        '<div class="hero-center">'
        f'<div class="logo-xl">{_logo_svg(94)}</div>'
        '<h1 class="wordmark">ARGUS</h1>'
        '<div class="hero-tag">Attack Surface Management</div>'
        '<p class="slogan">See everything. <b>Secure what matters.</b></p>'
        + pillars_html +
        '<p class="hero-desc">Plataforma de monitoramento de superfície de ataque — descoberta de '
        'ativos, varredura de portas e subdomínios, postura de e-mail e enriquecimento com '
        'inteligência de ameaças (AbuseIPDB · Certificate Transparency · urlscan.io · RDAP/WHOIS).</p>'
        '</div>\n'
    )
    return _portal_shell("", "Argus", "", hero + hub, show_head=False)


_DASH_SCRIPT = r"""<script>
async function loadKpis(url){
  try{ const r=await fetch(url,{cache:'no-store'}); if(!r.ok) return null;
    const t=await r.text();
    const m=t.match(/<script id="exm-kpis" type="application\/json">([\s\S]*?)<\/script>/);
    return m?JSON.parse(m[1]):null;
  }catch(e){ return null; }
}
function setTxt(id,v){ const e=document.getElementById(id); if(e) e.textContent=(v==null?'—':v); }
function escH(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function camps(listId, arr, href){
  const el=document.getElementById(listId); if(!el) return;
  if(!arr||!arr.length){ el.innerHTML='<div class="empty">Nenhuma campanha ainda.</div>'; return; }
  el.innerHTML=arr.map(c=>'<a class="list-row" style="text-decoration:none;color:inherit" href="'+href+'">'
    +'<span class="ic2">&#9656;</span><div><div class="nm">'+escH(c)+'</div>'
    +'<div class="dt">Ver no relatório</div></div></a>').join('');
}
(async()=>{
  const mon=await loadKpis('/monitor_report.html');
  const sub=await loadKpis('/submonitor_report.html');
  const cre=await loadKpis('/credentials_report.html');
  const g=(o,k)=>o&&typeof o[k]==='number'?o[k]:0;
  const crit=g(mon,'critico')+g(sub,'critico');
  const alto=g(mon,'alto')+g(sub,'alto');
  const med =g(mon,'medio')+g(sub,'medio');
  const baixo=g(mon,'baixo')+g(sub,'baixo');
  const info=g(mon,'info')+g(sub,'info');
  const assets=g(mon,'total')+g(sub,'total');
  const novos=g(mon,'novos')+g(sub,'novos');
  const abus=g(mon,'abusivos')+g(sub,'abusivos');
  setTxt('k-crit',crit); setTxt('k-alto',alto); setTxt('k-med',med);
  setTxt('k-assets',assets); setTxt('k-novos',novos); setTxt('k-abus',abus);
  const tot=crit+alto+med+baixo+info||1;
  const segs={'sb-crit':crit,'sb-alto':alto,'sb-med':med,'sb-baixo':baixo,'sb-info':info};
  for(const id in segs){ const e=document.getElementById(id); if(e) e.style.width=(segs[id]/tot*100)+'%'; }
  setTxt('lg-crit',crit); setTxt('lg-alto',alto); setTxt('lg-med',med); setTxt('lg-baixo',baixo); setTxt('lg-info',info);
  setTxt('m-total',g(mon,'total')); setTxt('m-crit',g(mon,'critico')); setTxt('m-ips',g(mon,'ips')); setTxt('m-udp',g(mon,'udp')); setTxt('m-vuln',g(mon,'vuln_ips')); setTxt('m-kev',g(mon,'kev'));
  setTxt('m-when',mon?mon.now:'sem dados');
  camps('m-camps',mon?mon.campanhas:[],'/monitor_report.html');
  setTxt('s-total',g(sub,'total')); setTxt('s-crit',g(sub,'critico')); setTxt('s-us',g(sub,'urlscan'));
  setTxt('s-when',sub?sub.now:'sem dados');
  camps('s-camps',sub?sub.campanhas:[],'/submonitor_report.html');
  setTxt('c-comp',g(cre,'comprometidos')); setTxt('c-emp',g(cre,'funcionarios')); setTxt('c-us',g(cre,'usuarios'));
  setTxt('c-when',cre?cre.now:'sem dados');
  camps('c-camps',cre?cre.campanhas:[],'/credentials_report.html');
  const eml=await loadKpis('/email_report.html');
  setTxt('e-total',g(eml,'total')); setTxt('e-spoof',g(eml,'spoofaveis')); setTxt('e-nodmarc',g(eml,'sem_dmarc'));
  setTxt('e-when',eml?eml.now:'sem dados');
  camps('e-camps',eml?eml.campanhas:[],'/email_report.html');
  const fnd=await loadKpis('/findings_report.html');
  setTxt('f-backlog',g(fnd,'backlog')); setTxt('f-crit',g(fnd,'critico'));
  setTxt('f-mitig',g(fnd,'mitig')); setTxt('f-fp',g(fnd,'fp')); setTxt('f-total',g(fnd,'total'));
  setTxt('f-when',fnd?fnd.now:'sem dados');
  const ty=await loadKpis('/typosquat_report.html');
  setTxt('ty-total',g(ty,'total')); setTxt('ty-crit',g(ty,'critico')); setTxt('ty-mx',g(ty,'com_mx'));
  setTxt('ty-when',ty?ty.now:'sem dados');
  camps('ty-camps',ty?ty.campanhas:[],'/typosquat_report.html');
  // Estado do Dashboard: nenhum relatório gerado = 1ª execução pendente; relatórios
  // gerados mas sem nenhum achado = superfície limpa; com achados = esconde os dois.
  const anyReport = !!(mon||sub||cre||eml||fnd||ty);
  const totalAll = assets + g(cre,'total') + g(eml,'total') + g(fnd,'total') + g(ty,'total');
  const pend=document.getElementById('dash-empty'), cln=document.getElementById('dash-clean');
  if(pend) pend.style.display = anyReport ? 'none' : 'flex';
  if(cln)  cln.style.display  = (anyReport && totalAll===0) ? 'flex' : 'none';
  // Card de Correlação: conta subdomínios, IPs únicos e IPs compartilhados (exm-rows).
  try{
    const sr=await fetch('/submonitor_report.html',{cache:'no-store'}).then(r=>r.ok?r.text():'').catch(()=>'');
    const mm=sr.match(/<script id="exm-rows" type="application\/json">([\s\S]*?)<\/script>/);
    let rows=[]; try{ rows=mm?JSON.parse(mm[1]):[]; }catch(e){}
    const hosts=new Set(), ips=new Set(), ipHosts={};
    rows.forEach(r=>{ if(r.h)hosts.add(r.h); if(r.ip){ips.add(r.ip); (ipHosts[r.ip]=ipHosts[r.ip]||new Set()).add(r.h);} });
    const shared=Object.values(ipHosts).filter(s=>s.size>1).length;
    setTxt('d-corr-sub',hosts.size); setTxt('d-corr-ip',ips.size); setTxt('d-corr-shared',shared);
  }catch(e){}
})();
</script>"""


def build_dashboard() -> str:
    kpi = (
        '<div class="kpi-grid">'
        '<div class="kpi sev-crit"><div class="v" id="k-crit">&mdash;</div><div class="l">Críticos</div></div>'
        '<div class="kpi sev-alto"><div class="v" id="k-alto">&mdash;</div><div class="l">Alto Risco</div></div>'
        '<div class="kpi sev-med"><div class="v" id="k-med">&mdash;</div><div class="l">Médio</div></div>'
        '<div class="kpi"><div class="v" id="k-assets">&mdash;</div><div class="l">Ativos totais</div></div>'
        '<div class="kpi sev-novo"><div class="v" id="k-novos">&mdash;</div><div class="l">Novos</div></div>'
        '<div class="kpi sev-abus" title="IPs com reputação ruim no AbuseIPDB (denúncias de abuso) ou saída TOR">'
        '<div class="v" id="k-abus">&mdash;</div><div class="l">IPs Abusivos</div></div>'
        '</div>'
    )
    sevbar = (
        '<div class="panel donut-card"><h2>Distribuição de Risco</h2>'
        '<div class="sbar" style="width:100%">'
        '<i id="sb-crit" style="background:var(--red);width:0"></i>'
        '<i id="sb-alto" style="background:var(--orange);width:0"></i>'
        '<i id="sb-med" style="background:var(--yellow);width:0"></i>'
        '<i id="sb-baixo" style="background:var(--green);width:0"></i>'
        '<i id="sb-info" style="background:var(--border-2);width:0"></i></div>'
        '<div class="legend" style="width:100%;margin-top:10px">'
        '<div class="legend-item"><span class="dot" style="background:var(--red)"></span>Crítico<b id="lg-crit">&mdash;</b></div>'
        '<div class="legend-item"><span class="dot" style="background:var(--orange)"></span>Alto<b id="lg-alto">&mdash;</b></div>'
        '<div class="legend-item"><span class="dot" style="background:var(--yellow)"></span>Médio<b id="lg-med">&mdash;</b></div>'
        '<div class="legend-item"><span class="dot" style="background:var(--green)"></span>Baixo<b id="lg-baixo">&mdash;</b></div>'
        '<div class="legend-item"><span class="dot" style="background:var(--border-2)"></span>Info<b id="lg-info">&mdash;</b></div>'
        '</div></div>'
    )
    summary = f'<div class="summary">{kpi}{sevbar}</div>'

    mon_panel = (
        '<div class="panel panel-pad">'
        f'<h2>{_NAV_ICONS["monitor"]} Monitor de Portas <span class="badge" id="m-when">&mdash;</span></h2>'
        '<div class="kpi-grid" style="margin-bottom:14px">'
        '<div class="kpi"><div class="v" id="m-total">&mdash;</div><div class="l">Portas</div></div>'
        '<div class="kpi sev-crit"><div class="v" id="m-crit">&mdash;</div><div class="l">Críticos</div></div>'
        '<div class="kpi"><div class="v" id="m-ips">&mdash;</div><div class="l">IPs únicos</div></div>'
        '<div class="kpi sev-crit"><div class="v" id="m-vuln">&mdash;</div><div class="l">Vulneráveis</div></div>'
        '<div class="kpi sev-crit" title="CISA KEV — Known Exploited Vulnerabilities: CVEs com exploração confirmada in-the-wild"><div class="v" id="m-kev">&mdash;</div><div class="l">Explorados (KEV)</div></div>'
        '<div class="kpi"><div class="v" id="m-udp">&mdash;</div><div class="l">Portas UDP</div></div></div>'
        '<div id="m-camps"><div class="empty">Carregando…</div></div>'
        '<a class="list-row" href="/monitor_report.html" style="text-decoration:none;color:inherit;margin-top:10px">'
        '<span class="ic2">&#9656;</span><div><div class="nm">Ver relatório completo</div></div></a></div>'
    )
    sub_panel = (
        '<div class="panel panel-pad">'
        f'<h2>{_NAV_ICONS["submonitor"]} Monitor de Subdomínios <span class="badge" id="s-when">&mdash;</span></h2>'
        '<div class="kpi-grid" style="margin-bottom:14px">'
        '<div class="kpi"><div class="v" id="s-total">&mdash;</div><div class="l">Subdomínios</div></div>'
        '<div class="kpi sev-crit"><div class="v" id="s-crit">&mdash;</div><div class="l">Críticos</div></div>'
        '<div class="kpi" title="Subdomínios já vistos em varreduras públicas do urlscan.io (descoberta passiva)">'
        '<div class="v" id="s-us">&mdash;</div><div class="l">Visto urlscan</div></div></div>'
        '<div id="s-camps"><div class="empty">Carregando…</div></div>'
        '<a class="list-row" href="/submonitor_report.html" style="text-decoration:none;color:inherit;margin-top:10px">'
        '<span class="ic2">&#9656;</span><div><div class="nm">Ver relatório completo</div></div></a></div>'
    )
    sched = (
        '<details class="panel panel-pad acc"><summary>&#x23F0; Agenda de Execução (cron)</summary>'
        '<div class="list-row"><span class="ic2">&#x1F5A5;</span><div>'
        '<div class="nm">argus-monitor <span class="pill-ok">ativo</span> <span class="badge">TCP</span></div>'
        '<div class="dt">Portas e serviços expostos &middot; diariamente às <b>10:00</b></div></div></div>'
        '<div class="list-row"><span class="ic2">&#x1F4E1;</span><div>'
        '<div class="nm">argus-monitor-udp <span class="pill-ok">ativo</span> <span class="badge">UDP</span></div>'
        '<div class="dt">100 portas UDP curadas &middot; domingos às <b>03:00</b></div></div></div>'
        '<div class="list-row"><span class="ic2">&#x1F310;</span><div>'
        '<div class="nm">argus-submonitor <span class="pill-ok">ativo</span></div>'
        '<div class="dt">Descoberta de subdomínios &middot; diariamente às <b>12:00</b></div></div></div>'
        '<div class="list-row"><span class="ic2">&#x1F511;</span><div>'
        '<div class="nm">argus-credentials <span class="pill-ok">ativo</span></div>'
        '<div class="dt">Vazamento de credenciais &middot; diariamente às <b>14:00</b></div></div></div>'
        '<div class="list-row"><span class="ic2">&#x2709;&#xFE0F;</span><div>'
        '<div class="nm">argus-email <span class="pill-ok">ativo</span></div>'
        '<div class="dt">Postura SPF/DMARC/DKIM &middot; diariamente às <b>13:00</b></div></div></div>'
        '<div class="list-row"><span class="ic2">&#x1F465;</span><div>'
        '<div class="nm">argus-typosquat <span class="pill-ok">ativo</span></div>'
        '<div class="dt">Domínios sósia (dnstwist) &middot; domingos às <b>05:00</b></div></div></div>'
        # Comandos/paths ficam em "Detalhes técnicos" recolhido — ruído para o uso diário.
        '<details class="adv" style="margin-top:10px"><summary style="cursor:pointer;color:var(--muted);'
        'font-size:12px;font-weight:600">Detalhes técnicos (comandos)</summary>'
        '<pre style="margin-top:8px;background:var(--bg);border:1px solid var(--border);border-radius:8px;'
        'padding:10px;font-size:11px;color:var(--muted);overflow:auto;white-space:pre-wrap">'
        'argus-monitor --tcp        # /etc/argus/monitor/monitor.py --tcp\n'
        'argus-monitor --udp        # /etc/argus/monitor/monitor.py --udp (100 portas)\n'
        'argus-submonitor           # /etc/argus/submonitor/submonitor.py\n'
        'argus-credentials          # /etc/argus/credentials/credentials.py\n'
        'argus-email                # /etc/argus/email/emailauth.py\n'
        'argus-typosquat            # /etc/argus/typosquat/typosquat.py (dnstwist)</pre></details>'
        '</details>'
    )
    info = (
        '<details class="panel panel-pad acc"><summary>&#x2139;&#xFE0F; Bases &amp; Logs</summary>'
        '<div class="list-row"><span class="ic2">&#x1F5C4;</span><div><div class="nm">Bancos SQLite</div>'
        '<div class="dt"><b>argus.db</b> (Gestão de Achados · store central) · monitor.db · submonitor.db · '
        'credentials.db · email.db · typosquat.db · threatintel.db (cache 48h) · intel.db '
        '(<abbr title="RDAP — Registration Data Access Protocol: sucessor moderno do WHOIS, retorna dados de registro de domínios em JSON">RDAP</abbr>) · acknowledged.db</div></div></div>'
        '<div class="list-row"><span class="ic2">&#x1F4DD;</span><div><div class="nm">Logs '
        '<abbr title="RFC 5424 — formato padrão de mensagens syslog (timestamp, severidade, host, app, dados estruturados)">RFC 5424</abbr></div>'
        '<div class="dt">/var/log/argus/{monitor · submonitor · credentials · email · typosquat}</div></div></div>'
        '<div class="list-row"><span class="ic2">&#x1F310;</span><div><div class="nm">Serviço Web (ações de achados)</div>'
        '<div class="dt">argus-web (Flask) atrás do Apache &middot; acesso por HTTPS com autenticação</div></div></div></details>'
    )
    cred_panel = (
        '<div class="panel panel-pad">'
        f'<h2>{_NAV_ICONS["credentials"]} Exposição de Credenciais <span class="badge" id="c-when">&mdash;</span></h2>'
        '<div class="kpi-grid" style="margin-bottom:14px">'
        '<div class="kpi sev-crit"><div class="v" id="c-comp">&mdash;</div><div class="l">Domínios exp.</div></div>'
        '<div class="kpi sev-crit"><div class="v" id="c-emp">&mdash;</div><div class="l">Funcionários</div></div>'
        '<div class="kpi sev-alto"><div class="v" id="c-us">&mdash;</div><div class="l">Usuários</div></div></div>'
        '<div id="c-camps"><div class="empty">Carregando…</div></div>'
        '<a class="list-row" href="/credentials_report.html" style="text-decoration:none;color:inherit;margin-top:10px">'
        '<span class="ic2">&#9656;</span><div><div class="nm">Ver relatório completo</div></div></a></div>'
    )
    email_panel = (
        '<div class="panel panel-pad">'
        f'<h2>{_NAV_ICONS["email"]} Postura de E-mail <span class="badge" id="e-when">&mdash;</span></h2>'
        '<div class="kpi-grid" style="margin-bottom:14px">'
        '<div class="kpi"><div class="v" id="e-total">&mdash;</div><div class="l">Domínios</div></div>'
        '<div class="kpi sev-crit" title="Domínios sem proteção anti-falsificação (SPF/DMARC fracos) — podem ser usados para forjar e-mails em seu nome">'
        '<div class="v" id="e-spoof">&mdash;</div><div class="l">Spoofáveis</div></div>'
        '<div class="kpi sev-alto"><div class="v" id="e-nodmarc">&mdash;</div><div class="l">Sem DMARC</div></div></div>'
        '<div id="e-camps"><div class="empty">Carregando…</div></div>'
        '<a class="list-row" href="/email_report.html" style="text-decoration:none;color:inherit;margin-top:10px">'
        '<span class="ic2">&#9656;</span><div><div class="nm">Ver relatório completo</div></div></a></div>'
    )
    findings_panel = (
        '<div class="panel panel-pad">'
        f'<h2>{_NAV_ICONS["findings"]} Gestão de Achados <span class="badge" id="f-when">&mdash;</span></h2>'
        '<div class="kpi-grid" style="margin-bottom:14px">'
        '<div class="kpi sev-alto"><div class="v" id="f-backlog">&mdash;</div><div class="l">Backlog</div></div>'
        '<div class="kpi sev-crit"><div class="v" id="f-crit">&mdash;</div><div class="l">Críticos</div></div>'
        '<div class="kpi"><div class="v" id="f-total">&mdash;</div><div class="l">Total</div></div></div>'
        '<div class="legend" style="width:100%">'
        '<div class="legend-item"><span class="dot" style="background:#6ee7b7"></span>Mitigado<b id="f-mitig">&mdash;</b></div>'
        '<div class="legend-item"><span class="dot" style="background:var(--border-2)"></span>Falso Positivo<b id="f-fp">&mdash;</b></div></div>'
        '<a class="list-row" href="/findings_report.html" style="text-decoration:none;color:inherit;margin-top:10px">'
        '<span class="ic2">&#9656;</span><div><div class="nm">Abrir gestão de achados</div>'
        '<div class="dt">status · tratativas · evidências (auditado)</div></div></a></div>'
    )
    typo_panel = (
        '<div class="panel panel-pad">'
        f'<h2>{_NAV_ICONS["typosquat"]} Typosquat <span class="badge" id="ty-when">&mdash;</span></h2>'
        '<div class="kpi-grid" style="margin-bottom:14px">'
        '<div class="kpi"><div class="v" id="ty-total">&mdash;</div><div class="l">Sósia</div></div>'
        '<div class="kpi sev-crit"><div class="v" id="ty-crit">&mdash;</div><div class="l">P/ phishing</div></div>'
        '<div class="kpi sev-alto"><div class="v" id="ty-mx">&mdash;</div><div class="l">Com MX</div></div></div>'
        '<div id="ty-camps"><div class="empty">Carregando…</div></div>'
        '<a class="list-row" href="/typosquat_report.html" style="text-decoration:none;color:inherit;margin-top:10px">'
        '<span class="ic2">&#9656;</span><div><div class="nm">Ver relatório completo</div></div></a></div>'
    )
    corr_panel = (
        '<div class="panel panel-pad">'
        f'<h2>{_NAV_ICONS["correlacao"]} Correlação</h2>'
        '<div class="kpi-grid" style="margin-bottom:14px">'
        '<div class="kpi"><div class="v" id="d-corr-sub">&mdash;</div><div class="l">Subdomínios</div></div>'
        '<div class="kpi"><div class="v" id="d-corr-ip">&mdash;</div><div class="l">IPs únicos</div></div>'
        '<div class="kpi sev-abus" title="IPs servindo mais de um subdomínio — possível ponto único de falha">'
        '<div class="v" id="d-corr-shared">&mdash;</div><div class="l">IPs compartilhados</div></div></div>'
        '<a class="list-row" href="/correlacao.html" style="text-decoration:none;color:inherit;margin-top:10px">'
        '<span class="ic2">&#9656;</span><div><div class="nm">Abrir mapa de correlação</div>'
        '<div class="dt">subdomínios × IPs · ponto único de falha</div></div></a></div>'
    )
    sources = ('<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:16px">'
               + findings_panel + mon_panel + sub_panel + corr_panel + cred_panel + email_panel + typo_panel + '</div>')
    # Estado vazio do Dashboard (mesmo padrão das páginas internas): desfaz a ambiguidade
    # "zero por falta de coleta" × "zero por ausência de risco". JS ajusta após carregar.
    banner = (
        '<div id="dash-empty" class="panel panel-pad" style="border-left:3px solid var(--accent);'
        'margin-bottom:16px;display:flex;gap:14px;align-items:flex-start">'
        '<span style="font-size:22px" aria-hidden="true">&#x23F3;</span>'
        '<div><div style="font-weight:700;font-size:15px;color:var(--text);margin-bottom:4px">Primeira execução pendente</div>'
        '<div style="color:var(--muted);font-size:13px;line-height:1.6">O Argus ainda não coletou dados. Os scans rodam '
        'automaticamente (Portas <b>10:00</b>, Subdomínios <b>12:00</b>, E-mail <b>13:00</b>, Credenciais <b>14:00</b>, '
        'Typosquat domingos <b>05:00</b>). <b>Os zeros abaixo significam &ldquo;ainda sem coleta&rdquo;, não &ldquo;ausência '
        'de risco&rdquo;.</b> Para ver agora, rode no servidor: <code>sudo argus-monitor --tcp</code>.</div></div></div>'
    )
    clean = (
        '<div id="dash-clean" class="panel panel-pad" style="display:none;border-left:3px solid var(--green);'
        'margin-bottom:16px;gap:14px;align-items:flex-start">'
        '<span style="font-size:22px" aria-hidden="true">&#x2705;</span>'
        '<div><div style="font-weight:700;font-size:15px;color:var(--text);margin-bottom:4px">Nenhum achado até agora</div>'
        '<div style="color:var(--muted);font-size:13px;line-height:1.6">Os scans já rodaram e <b>não encontraram exposições</b> '
        'na superfície monitorada. Os zeros abaixo refletem ausência de risco, não falta de dados.</div></div></div>'
    )
    body = banner + clean + summary + '\n' + sources + '\n' \
        + '<div class="grid-2" style="margin-top:16px">' + sched + info + '</div>'
    return _portal_shell("dashboard", "Dashboard",
                         "Visão consolidada da superfície de ataque: portas, subdomínios, "
                         "credenciais, e-mail, typosquat e gestão de achados", body,
                         extra_script=_DASH_SCRIPT)


def build_risk_guide() -> str:
    # Cada seção recebe uma âncora (aid) para o índice e um link "voltar ao topo".
    def panel(title, inner, aid=None, toc_label=None):
        idattr = f' id="{aid}"' if aid else ""
        top = ('<a href="#top" title="Voltar ao topo" style="margin-left:auto;font-size:11px;'
               'font-weight:600;color:var(--muted);text-decoration:none">&#x25B2; topo</a>') if aid else ""
        return f'<div class="panel panel-pad sect"{idattr} style="margin-bottom:16px"><h2>{title}{top}</h2>{inner}</div>'

    overview = panel("Visão Geral",
        '<p>O Argus classifica risco por <b>evidência</b>, não por suposição. Ele começa de uma '
        '<b>base de exposição</b> (porta/serviço exposto, IP público vs. privado) e <b>eleva</b> conforme as '
        'evidências objetivas: reputação do <b>AbuseIPDB</b>, vulnerabilidade conhecida (<b>Shodan/CVE</b>), '
        'exploração confirmada in-the-wild (<b>CISA KEV</b>) e nota <b>CVSS</b> (NVD). '
        '<b>O risco nunca é rebaixado</b> — só elevado. Contexto interno (ambiente, etc.) é validado pelo analista.</p>'
        '<div class="flow">'
        '<div class="flow-step"><div class="l">Exposição</div><div class="v">Porta / IP público</div></div>'
        '<div class="flow-arrow">+</div>'
        '<div class="flow-step"><div class="l">Reputação</div><div class="v">AbuseIPDB</div></div>'
        '<div class="flow-arrow">+</div>'
        '<div class="flow-step"><div class="l">Vulnerabilidade</div><div class="v">CVE · KEV · CVSS</div></div>'
        '<div class="flow-arrow">&#x2192;</div>'
        '<div class="flow-step res"><div class="l">Resultado</div><div class="v">Risco final</div></div></div>',
        aid="rg-overview", toc_label="Visão geral")

    ports = panel("&#x1F5A5; Monitor de Portas",
        '<table class="risk-table"><thead><tr><th>Porta / Serviço</th><th>IP Público</th>'
        '<th>IP Privado</th><th>Justificativa</th></tr></thead><tbody>'
        '<tr><td>23 — Telnet</td><td class="r-critico">CRÍTICO</td><td class="r-critico">CRÍTICO</td><td>Sem criptografia, obsoleto</td></tr>'
        '<tr><td>3389 — RDP</td><td class="r-critico">CRÍTICO</td><td class="r-alto">ALTO</td><td>Acesso remoto, alvo frequente</td></tr>'
        '<tr><td>445 — SMB</td><td class="r-critico">CRÍTICO</td><td class="r-alto">ALTO</td><td>Ransomware / movimentação lateral</td></tr>'
        '<tr><td>3306 — MySQL</td><td class="r-critico">CRÍTICO</td><td class="r-alto">ALTO</td><td>Banco exposto</td></tr>'
        '<tr><td>2375 — Docker API</td><td class="r-critico">CRÍTICO</td><td class="r-critico">CRÍTICO</td><td>Root no host via container</td></tr>'
        '<tr><td>22 — SSH</td><td class="r-medio">MÉDIO</td><td class="r-baixo">BAIXO</td><td>Seguro, mas alvo de brute force</td></tr>'
        '<tr><td>80/443 — HTTP/S</td><td class="r-baixo">BAIXO</td><td class="r-baixo">BAIXO</td><td>Serviço web padrão</td></tr>'
        '</tbody></table>',
        aid="rg-ports", toc_label="Monitor de Portas")

    ports_udp = panel("&#x1F4E1; Portas UDP <span class=\"chip\">--udp · semanal</span>",
        '<p style="margin-bottom:10px">Varredura UDP <b>opt-in</b> (<code>argus-monitor --udp</code>, cron semanal) '
        'de <b>100 portas curadas por criticidade</b> — OOB/ICS/RCE, VPN/DNS/SIP, <i>poisoning</i> e refletores de '
        'amplificação. UDP é lento e ambíguo, então a lista é fixa e só reporta portas confirmadas abertas.</p>'
        '<table class="risk-table"><thead><tr><th>Categoria</th><th>Portas (ex.)</th><th>IP Público</th><th>Por quê</th></tr></thead><tbody>'
        '<tr><td><abbr title="Out-of-Band — gestão fora de banda">OOB</abbr> / '
        '<abbr title="Industrial Control Systems — sistemas de automação industrial">ICS</abbr> / '
        '<abbr title="Remote Code Execution — execução remota de código">RCE</abbr></td>'
        '<td>623 IPMI · 17185 VxWorks · 69 TFTP · 47808 BACnet · 20000 DNP3 · 44818 EtherNet/IP</td><td class="r-critico">CRÍTICO</td><td>Gestão out-of-band, automação industrial, exec remota</td></tr>'
        '<tr><td>Info / poisoning / amplificação</td><td>161 SNMP · 389 CLDAP · 11211 memcached · 137/138 NetBIOS · 5355 LLMNR · 19 chargen</td><td class="r-critico">CRÍTICO</td><td>Vazamento massivo, roubo de credencial, refletor DDoS</td></tr>'
        '<tr><td>Acesso / VPN / DNS / VoIP</td><td>3389 RDP · 500/4500 IPsec · 1194 OpenVPN · 53 DNS · 5060 SIP · 1812 RADIUS</td><td class="r-alto">ALTO</td><td>Endpoints de acesso/autenticação expostos</td></tr>'
        '<tr><td>Infra / telemetria / mídia</td><td>67/68 DHCP · 2055 NetFlow · 5246 CAPWAP · 3478 STUN · jogos</td><td class="r-medio">MÉDIO</td><td>Roteamento, telemetria, mídia e refletores menores</td></tr>'
        '<tr><td>Web moderno</td><td>443 QUIC / HTTP-3</td><td class="r-baixo">BAIXO</td><td>Serviço web legítimo sobre UDP</td></tr>'
        '</tbody></table>'
        '<p style="margin-top:10px"><b>Nota:</b> a criticidade UDP usa tabela própria (o serviço difere do TCP) e também '
        'eleva por IP público × privado e por reputação AbuseIPDB, como no TCP.</p>'
        '<p class="empty" style="margin-top:8px"><b>Siglas:</b> '
        'OOB (out-of-band) · ICS (controle industrial) · RCE (execução remota de código) · '
        'CLDAP (Connectionless LDAP) · CAPWAP (controle de access points) · STUN (NAT traversal) · '
        'LLMNR/NetBIOS (resolução de nomes Windows).</p>',
        aid="rg-udp", toc_label="Portas UDP")

    subs = panel("&#x1F310; Monitor de Subdomínios",
        '<table class="risk-table"><thead><tr><th>Base (exposição)</th><th>Risco base</th><th>Exemplo</th></tr></thead><tbody>'
        '<tr><td>Subdomínio em IP <b>público</b></td><td class="r-medio">MÉDIO</td><td>api.empresa.com.br</td></tr>'
        '<tr><td>Subdomínio em IP <b>privado</b></td><td class="r-baixo">BAIXO</td><td>intranet.empresa.com.br</td></tr>'
        '</tbody></table>'
        '<p style="margin-top:10px">O risco base reflete só a <b>exposição</b>: estar em IP público é a superfície '
        'externa (MÉDIO — vale revisar); IP privado fica de fora (BAIXO). <b>Não há mais suposição</b> sobre ambiente '
        '(dev/prod) nem WAF — isso é contexto da empresa, que o analista valida. O risco então sobe por '
        '<b>evidência</b>:</p>'
        '<table class="risk-table" style="margin-top:8px"><thead><tr><th>Evidência</th><th>Efeito no risco</th></tr></thead><tbody>'
        '<tr><td>Reputação ruim no AbuseIPDB</td><td class="r-alto">eleva (até CRÍTICO)</td></tr>'
        '<tr><td><span class="b-crit">CVE</span> conhecida (Shodan)</td><td class="r-alto">no mínimo ALTO</td></tr>'
        '<tr><td>CVE <b>explorada in-the-wild</b> (CISA KEV)</td><td class="r-critico">CRÍTICO</td></tr>'
        '<tr><td>CVSS alto (NVD)</td><td class="r-alto">ALTO / CRÍTICO conforme a nota</td></tr>'
        '</tbody></table>',
        aid="rg-subs", toc_label="Subdomínios")

    abuse = panel("&#x1F6E1; Elevação por AbuseIPDB",
        '<div class="sbar"><i style="background:var(--green)"></i><i style="background:var(--yellow)"></i>'
        '<i style="background:var(--orange)"></i><i style="background:var(--red)"></i></div>'
        '<table class="risk-table" style="margin-top:12px"><thead><tr><th>Condição</th><th>Efeito</th></tr></thead><tbody>'
        '<tr><td><span class="b-crit">Score &ge; 80</span></td><td class="r-critico">Eleva para CRÍTICO</td></tr>'
        '<tr><td><span class="b-alto">Score &ge; 50</span></td><td class="r-alto">Mínimo ALTO</td></tr>'
        '<tr><td><span class="b-med">Porta crítica + Score &gt; 25</span></td><td class="r-critico">Eleva para CRÍTICO</td></tr>'
        '<tr><td>Node TOR</td><td class="r-alto">+1 nível</td></tr>'
        '<tr><td>Datacenter/Hosting + Score &gt; 0</td><td class="r-alto">+1 nível</td></tr>'
        '</tbody></table>',
        aid="rg-abuse", toc_label="Elevação por AbuseIPDB")

    vulns = panel("&#x1F41B; Vulnerabilidades (Shodan InternetDB) <span class=\"chip\">free · sem chave</span>",
        '<p style="margin-bottom:10px">Enriquecimento <b>passivo por IP</b> (último crawl do Shodan, sem chave): '
        '<b>CVEs conhecidas</b>, portas vistas, '
        '<abbr title="Common Platform Enumeration — identificador padronizado de produto/versão (ex.: cpe:/a:apache:http_server:2.4)">CPEs</abbr> e tags. '
        'Aplica a portas (monitor) e subdomínios (submonitor) — '
        'coluna <b>CVEs</b> + KPI <b>IPs vulneráveis</b> + filtro.</p>'
        '<table class="risk-table"><thead><tr><th>Condição</th><th>Efeito no risco</th></tr></thead><tbody>'
        '<tr><td>IP com <span class="b-crit">&ge; 1 CVE</span> conhecida</td><td class="r-alto">Eleva para no mínimo ALTO</td></tr>'
        '<tr><td>CVE + porta crítica / IP abusivo</td><td class="r-critico">Pode chegar a CRÍTICO (pelas outras camadas)</td></tr>'
        '<tr><td>Sem CVE</td><td>Sem efeito</td></tr>'
        '</tbody></table>'
        '<p style="margin-top:10px"><b>Cautela:</b> o matching de CVE do Shodan é heurístico (banner/CPE) e pode ter '
        '<b>falso-positivo</b> — por isso a elevação é conservadora (CVE sozinha não força CRÍTICO). Trate os CVEs como '
        '<i>leads a validar</i>. Dado <b>passivo/histórico</b>: pode não ver o que está atrás de firewall que bloqueia o Shodan.</p>',
        aid="rg-vulns", toc_label="Vulnerabilidades (Shodan)")

    origem = panel("&#x1F50E; Origem da Descoberta",
        '<table class="risk-table"><thead><tr><th>Origem</th><th>Técnica</th><th>Significado</th></tr></thead><tbody>'
        '<tr><td><span class="b-bai">wordlist</span></td><td>Enumeração ativa</td><td>Nomes testados da subs.txt</td></tr>'
        '<tr><td><span class="origem-crtsh">crt.sh</span></td><td>Certificate Transparency (passiva)</td><td>Revelado por certificados emitidos</td></tr>'
        '<tr><td><span class="origem-urlscan">urlscan</span></td><td>urlscan.io Search (passiva)</td><td>Visto em scans históricos públicos</td></tr>'
        '</tbody></table>',
        aid="rg-origem", toc_label="Origem da descoberta")

    whois = panel("&#x1F4C5; Inteligência de Domínio (RDAP/WHOIS)",
        '<table class="risk-table"><thead><tr><th>Classificação</th><th>Critério</th><th>Relevância CTI</th></tr></thead><tbody>'
        '<tr><td><span class="b-crit">NOVO</span></td><td>&lt; 30 dias</td><td>Forte indício de phishing</td></tr>'
        '<tr><td><span class="b-med">RECENTE</span></td><td>&lt; 1 ano</td><td>Merece atenção</td></tr>'
        '<tr><td><span class="b-bai">ESTABELECIDO</span></td><td>&gt; 1 ano</td><td>Infra madura</td></tr>'
        '<tr><td><span class="b-med">EXPIRANDO</span></td><td>&lt; 30 dias p/ expirar</td><td>Risco de sequestro por lapso</td></tr>'
        '<tr><td><span class="b-crit">EXPIRADO</span></td><td>Já expirou</td><td>Pode ser registrado por terceiros</td></tr>'
        '</tbody></table>',
        aid="rg-whois", toc_label="Inteligência de domínio")

    email = panel("&#x2709;&#xFE0F; Postura de E-mail (SPF / DMARC / DKIM)",
        '<table class="risk-table"><thead><tr><th>Condição</th><th>Risco</th><th>Por quê</th></tr></thead><tbody>'
        '<tr><td>SPF <code>+all</code> ou sem SPF <b>e</b> sem DMARC</td><td class="r-critico">CRÍTICO</td><td>Domínio totalmente spoofável</td></tr>'
        '<tr><td>Sem SPF · DMARC ausente ou <code>p=none</code> · SPF inválido</td><td class="r-alto">ALTO</td><td>Não bloqueia falsificação do remetente</td></tr>'
        '<tr><td>DMARC <code>p=quarantine</code> · SPF <code>~all</code>/<code>?all</code> · sem DKIM</td><td class="r-medio">MÉDIO</td><td>Proteção parcial / endurecer</td></tr>'
        '<tr><td>SPF <code>-all</code> + DMARC <code>p=reject</code> + DKIM</td><td class="r-baixo">BAIXO</td><td>Postura forte (anti-spoofing)</td></tr>'
        '</tbody></table>'
        '<p style="margin-top:10px"><b>Nota:</b> domínios <i>sem</i> MX também são verificados — um '
        'domínio que não envia e-mail ainda deve ter <code>-all</code> + <code>p=reject</code> para impedir '
        'spoofing. O DKIM é <i>best-effort</i> (sonda seletores comuns), pois o seletor não é descobrível de forma genérica.</p>',
        aid="rg-email", toc_label="Postura de e-mail")

    try:
        import findings as _fm
        _ctrl, _cat = _fm.CONTROLS_BY_SOURCE, _fm.CATEGORY_BY_SOURCE
    except Exception:
        _ctrl, _cat = {}, {}
    compliance = ""
    if _ctrl:
        crows = ""
        for src in ("monitor", "submonitor", "credentials", "email", "typosquat"):
            c = _ctrl.get(src)
            if not c:
                continue
            crows += ('<tr><td>' + _h(_cat.get(src, src)) + '</td>'
                      '<td>' + _h(" · ".join(c.get("iso", []))) + '</td>'
                      '<td>' + _h(" · ".join(c.get("cis", []))) + '</td>'
                      '<td>' + (_h(" · ".join(c.get("pci", []))) or "&mdash;") + '</td></tr>')
        compliance = panel("&#x1F4D8; Mapeamento de Conformidade <span class=\"chip\">ISO 27002 · CIS v8 · PCI-DSS</span>",
            '<p style="margin-bottom:10px">Cada tipo de achado é associado aos controles <b>realmente pertinentes</b> '
            '(sem compliance de marketing) — base para evidências de auditoria e priorização por conformidade. '
            'O mapeamento também aparece no detalhe de cada achado (Gestão de Achados).</p>'
            '<table class="risk-table rt-fixed">'
            '<colgroup><col style="width:20%"><col style="width:30%"><col style="width:28%"><col style="width:22%"></colgroup>'
            '<thead><tr><th>Categoria de achado</th><th>ISO/IEC 27002:2022</th>'
            '<th>CIS Controls v8</th><th>PCI-DSS v4.0</th></tr></thead><tbody>' + crows + '</tbody></table>',
            aid="rg-compliance", toc_label="Mapeamento de conformidade")

    # Índice (TOC) montado na MESMA ordem do corpo — âncoras navegáveis.
    body_sections = [overview, ports, ports_udp, subs, abuse, vulns]
    toc_items = [("rg-overview", "Visão geral"), ("rg-ports", "Monitor de Portas"),
                 ("rg-udp", "Portas UDP"), ("rg-subs", "Subdomínios"),
                 ("rg-abuse", "Elevação por AbuseIPDB"), ("rg-vulns", "Vulnerabilidades (Shodan)")]
    if compliance:
        body_sections.append(compliance)
        toc_items.append(("rg-compliance", "Mapeamento de conformidade"))
    body_sections += [origem, whois, email]
    toc_items += [("rg-origem", "Origem da descoberta"), ("rg-whois", "Inteligência de domínio"),
                  ("rg-email", "Postura de e-mail")]
    toc_links = "".join(
        f'<a href="#{aid}" style="text-decoration:none;font-size:12px;font-weight:600;color:var(--muted);'
        f'background:var(--surface);border:1px solid var(--border);border-radius:999px;padding:4px 12px">{label}</a>'
        for aid, label in toc_items)
    toc = ('<div class="panel panel-pad" id="top" style="margin-bottom:16px">'
           '<h2 style="font-size:14px;color:var(--accent);text-transform:uppercase;letter-spacing:.7px;'
           'margin-bottom:12px">&#x1F4D1; Índice</h2>'
           f'<div style="display:flex;flex-wrap:wrap;gap:8px">{toc_links}</div></div>')
    body = toc + "".join(body_sections)
    return _portal_shell("risk", "Guia de Risco",
                         "Como o Risk Engine calcula o risco de cada ativo", body)


_CORR_SCRIPT = r"""<script>
(function(){
  var SEV={CRITICO:'#f43f5e',ALTO:'#fb923c',MEDIO:'#fbbf24',BAIXO:'#34d399',INFO:'#8a99b4'};
  var SEVKEYS=['CRITICO','ALTO','MEDIO','BAIXO','INFO'];
  var TLBL={campaign:'Campanha',domain:'Domínio',subdomain:'Subdomínio',ip:'IP',
            email:'Achado · postura de e-mail',cred:'Achado · credenciais',typo:'Achado · typosquat'};
  var RAD={campaign:14,domain:11,subdomain:8,ip:9,email:9,cred:8,typo:9};
  var N={}, EDGES=[], EDGES_IP=[], ADJ={}, PAR={}, INDEG={}, open={}, POS={}, PIN={}, sel=null, _ids=[], _vis={}, selRoots=null;
  var viewMode='sub', sevSet={CRITICO:1,ALTO:1,MEDIO:1,BAIXO:1,INFO:1};
  var drag=null, dragMoved=false, ox=0, oy=0, sx=0, sy=0, vb={x:0,y:0,w:960,h:600}, pan=null, dragging=false;
  function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function setTxt(id,v){var e=document.getElementById(id); if(e)e.textContent=v;}
  function showOnly(id){['corr-empty','corr-off','corr-main'].forEach(function(x){var e=document.getElementById(x);if(e)e.style.display=(x===id?'block':'none');});}
  function curCamp(){ var s=document.getElementById('corr-camp'); return s?s.value:'*'; }
  // Monta a lista de adjacência da visão ATUAL (por subdomínio ou por IP).
  function rebuildAdj(){ var E=(viewMode==='ip')?EDGES_IP:EDGES; ADJ={}; PAR={}; INDEG={};
    E.forEach(function(e){ (ADJ[e[0]]=ADJ[e[0]]||[]).push(e[1]); (PAR[e[1]]=PAR[e[1]]||[]).push(e[0]); INDEG[e[1]]=(INDEG[e[1]]||0)+1; }); }
  function start(){
    fetch('/api/correlation',{cache:'no-store'}).then(function(r){return r.ok?r.json():null;}).then(function(j){
      if(!j||!j.ok){ showOnly('corr-off'); return; }
      if(!j.nodes||!j.nodes.length){ showOnly('corr-empty'); return; }
      N={}; j.nodes.forEach(function(n){N[n.id]=n;});
      EDGES=j.edges||[]; EDGES_IP=j.edges_ip||j.edges||[]; viewMode='sub'; rebuildAdj();
      showOnly('corr-main'); bindDrag();
      var st=j.stats||{}; setTxt('corr-nsub',st.subdomains||0); setTxt('corr-nip',st.ips||0); setTxt('corr-nshared',st.shared_ips||0);
      var camps=j.nodes.filter(function(n){return n.type==='campaign';}).map(function(n){return n.label;}).sort();
      var s=document.getElementById('corr-camp'); s.innerHTML='';
      var o0=document.createElement('option'); o0.value='*'; o0.textContent='Todas as campanhas'; s.appendChild(o0);
      camps.forEach(function(c){var o=document.createElement('option');o.value=c;o.textContent=c;s.appendChild(o);});
      s.value=camps.length===1?camps[0]:'*';
      s.onchange=function(){ sel=null; selRoots=null; hideDetail(); render(s.value); };
      var v=document.getElementById('corr-view'); if(v){ v.value='sub'; v.onchange=function(){ setView(v.value); }; }
      syncSevButtons();
      render(s.value);
    }).catch(function(){ showOnly('corr-off'); });
  }
  function hideDetail(){ var d=document.getElementById('corr-detail'); if(d)d.style.display='none'; }
  // Troca a orientação do grafo (subdomínio↔IP): refaz adjacências e relança o layout.
  function setView(m){ viewMode=m; rebuildAdj(); POS={}; PIN={}; open={}; sel=null; selRoots=null; hideDetail(); render(curCamp()); }
  // Filtro de severidade (item 2): mostra só os níveis ligados (multi-seleção).
  window.__corrSev=function(k){ if(k==='all'){ SEVKEYS.forEach(function(x){sevSet[x]=1;}); } else { sevSet[k]=sevSet[k]?0:1; }
    sel=null; selRoots=null; hideDetail(); syncSevButtons(); render(curCamp()); };
  function sevActive(){ return SEVKEYS.some(function(k){return !sevSet[k];}); }   // algum nível desligado?
  function syncSevButtons(){ SEVKEYS.forEach(function(k){ var b=document.getElementById('sevb-'+k); if(b){ b.classList.toggle('off',!sevSet[k]); } }); }
  function roots(camp){ var rs=Object.keys(N).filter(function(id){return N[id].type==='campaign' && (camp==='*'||N[id].label===camp);}); if(selRoots){ Object.keys(selRoots).forEach(function(r){ if(rs.indexOf(r)<0)rs.push(r); }); } return rs; }
  function kids(id){ return (ADJ[id]||[]).length>0; }
  function parentsOf(id){ return PAR[id]||[]; }   // O(1) — mapa pré-computado no rebuildAdj
  function rootsOf(id){ var rs={},st=[id],seen={}; while(st.length){ var x=st.pop(); if(seen[x])continue; seen[x]=1; if(N[x]&&N[x].type==='campaign'){rs[x]=1;continue;} parentsOf(x).forEach(function(p){st.push(p);}); } return Object.keys(rs); }
  function revealAncestors(id){ var st=parentsOf(id),seen={}; while(st.length){ var p=st.pop(); if(seen[p])continue; seen[p]=1; open[p]=true; parentsOf(p).forEach(function(g){st.push(g);}); } }
  function degOf(id){ var n=N[id]; return (n&&n.deg!=null)?n.deg:(INDEG[id]||0); }   // nº de subdomínios do IP
  function isShared(id){ var n=N[id]; return !!(n&&n.type==='ip'&&degOf(id)>1); }
  function isLeaf(id){ var n=N[id]; return !!(n&&['subdomain','ip','email','cred','typo'].indexOf(n.type)>=0); }
  function neighbors(id){ var s={}; s[id]=1; (ADJ[id]||[]).forEach(function(c){s[c]=1;}); parentsOf(id).forEach(function(p){s[p]=1;}); return s; }
  function expandVisible(rts){ var vis={}; rts.forEach(function(r){vis[r]=1;}); var ch=true;
    while(ch){ ch=false; Object.keys(vis).forEach(function(id){ if(open[id]&&ADJ[id]) ADJ[id].forEach(function(c){ if(!vis[c]){vis[c]=1;ch=true;} }); }); } return vis; }
  // Expande TUDO a partir das raízes (ignora estado recolhido) — usado pelo filtro de
  // severidade, que precisa achar as folhas mesmo sem o usuário ter expandido a árvore.
  function expandAll(rts){ var vis={},st=rts.slice(); rts.forEach(function(r){vis[r]=1;});
    while(st.length){ var id=st.pop(); (ADJ[id]||[]).forEach(function(c){ if(!vis[c]){vis[c]=1;st.push(c);} }); } return vis; }
  // Aplica o filtro de severidade: mantém folhas com nível ligado + seus contêineres
  // ancestrais (campanha/domínio). Sobe SÓ por contêiner — nunca por outra folha — para
  // um IP compartilhado mantido não arrastar um subdomínio-irmão de outro nível.
  function sevFilter(vis){ var keep={}; Object.keys(vis).forEach(function(id){ if(isLeaf(id)&&sevSet[N[id].risk]) keep[id]=1; });
    var ch=true; while(ch){ ch=false; Object.keys(keep).forEach(function(id){ parentsOf(id).forEach(function(p){ if(vis[p]&&!keep[p]&&!isLeaf(p)){keep[p]=1;ch=true;} }); }); } return keep; }
  function visible(rts){ if(sevActive()) return sevFilter(expandAll(rts)); return expandVisible(rts); }
  function layout(ids,W,H){
    var freshSet={}, fresh=[];
    ids.forEach(function(id){ if(!POS[id]){ freshSet[id]=1; fresh.push(id); var p=null; parentsOf(id).forEach(function(s){ if(POS[s]) p=POS[s]; });
      var bx=p?p.x:W/2, by=p?p.y:H/2; POS[id]={x:bx+(Math.random()*60-30),y:by+(Math.random()*60-30),vx:0,vy:0}; } });
    if(fresh.length===0) return;   // nada novo entrou → mantém o layout estável (sem "pulo" ao clicar)
    ids.forEach(function(id){POS[id].vx=0;POS[id].vy=0;});
    var iters=ids.length>220?120:260;
    for(var it=0;it<iters;it++){
      for(var i=0;i<ids.length;i++)for(var j=i+1;j<ids.length;j++){ var a=POS[ids[i]],b=POS[ids[j]],dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy||0.01,d=Math.sqrt(d2),f=2300/d2,fx=dx/d*f,fy=dy/d*f; a.vx+=fx;a.vy+=fy;b.vx-=fx;b.vy-=fy; }
      ids.forEach(function(s){ (ADJ[s]||[]).forEach(function(t){ if(!POS[t])return; var a=POS[s],b=POS[t],dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||0.01,f=(d-86)*0.045,fx=dx/d*f,fy=dy/d*f; a.vx+=fx;a.vy+=fy;b.vx-=fx;b.vy-=fy; }); });
      ids.forEach(function(id){ if(PIN[id]||!freshSet[id])return; var p=POS[id]; p.vx+=(W/2-p.x)*0.006; p.vy+=(H/2-p.y)*0.006; p.x+=Math.max(-14,Math.min(14,p.vx))*0.85; p.y+=Math.max(-14,Math.min(14,p.vy))*0.85; p.vx*=0.85;p.vy*=0.85; });
    }
    ids.forEach(function(id){ if(PIN[id]||!freshSet[id])return; var p=POS[id]; p.x=Math.max(36,Math.min(W-36,p.x)); p.y=Math.max(30,Math.min(H-30,p.y)); });
  }
  function shapeEl(type,x,y,r,fill,stroke,sw){
    var c=' fill="'+fill+'" stroke="'+stroke+'" stroke-width="'+sw+'"/>';
    if(type==='ip'){ return '<polygon points="'+x+','+(y-r)+' '+(x+r)+','+y+' '+x+','+(y+r)+' '+(x-r)+','+y+'"'+c; }
    if(type==='email'){ return '<polygon points="'+x+','+(y-r)+' '+(x+r*0.92).toFixed(1)+','+(y+r*0.72).toFixed(1)+' '+(x-r*0.92).toFixed(1)+','+(y+r*0.72).toFixed(1)+'"'+c; }
    if(type==='cred'){ var hh=(r*0.9); return '<rect x="'+(x-hh).toFixed(1)+'" y="'+(y-hh).toFixed(1)+'" width="'+(2*hh).toFixed(1)+'" height="'+(2*hh).toFixed(1)+'" rx="2"'+c; }
    if(type==='typo'){ var pts=[]; for(var i=0;i<6;i++){var a=Math.PI/180*(60*i-30); pts.push((x+r*Math.cos(a)).toFixed(1)+','+(y+r*Math.sin(a)).toFixed(1));} return '<polygon points="'+pts.join(' ')+'"'+c; }
    return '<circle cx="'+x+'" cy="'+y+'" r="'+r+'"'+c;
  }
  function paint(){
    var svg=document.getElementById('corr-svg'); if(!svg)return; var h='';
    // Desenha a aresta se AMBAS as pontas estão visíveis (não exige o pai expandido).
    Object.keys(_vis).forEach(function(s){ (ADJ[s]||[]).forEach(function(t){ if(!_vis[t])return; var a=POS[s],b=POS[t],sh=isShared(t)||isShared(s);
      h+='<line data-s="'+esc(s)+'" data-t="'+esc(t)+'" x1="'+a.x.toFixed(0)+'" y1="'+a.y.toFixed(0)+'" x2="'+b.x.toFixed(0)+'" y2="'+b.y.toFixed(0)+'" stroke="'+(sh?'#fb923c':'var(--border-2)')+'" stroke-width="'+(sh?1.6:0.7)+'"/>'; }); });
    _ids.forEach(function(id){ var n=N[id],p=POS[id],x=+p.x.toFixed(0),y=+p.y.toFixed(0),r=RAD[n.type]||8,c=SEV[n.risk]||'#8a99b4',sh=isShared(id),ring=(kids(id)&&!open[id]);
      h+='<g class="corr-node" tabindex="0" role="button" aria-label="'+esc(n.label)+', '+esc(TLBL[n.type]||n.type)+', risco '+esc(n.risk)+'" data-id="'+esc(id)+'">';
      h+='<title>'+esc(n.label)+' — '+esc(TLBL[n.type]||n.type)+'</title>';
      if(ring) h+='<circle cx="'+x+'" cy="'+y+'" r="'+(r+4)+'" fill="none" stroke="'+c+'" stroke-width="0.7" stroke-dasharray="2 2"/>';
      if(sh)   h+='<circle cx="'+x+'" cy="'+y+'" r="'+(r+4)+'" fill="none" stroke="#fb923c" stroke-width="1.6"/>';
      h+=shapeEl(n.type,x,y,r,c,(id===sel?'var(--text)':c),(id===sel?2.2:1));
      if(n.type==='campaign'||n.type==='domain'||sh||id===sel){ var lbl=n.label.length>26?n.label.slice(0,25)+'…':n.label;
        h+='<text x="'+x+'" y="'+(y+r+12)+'" text-anchor="middle" font-size="11" fill="var(--muted)">'+esc(lbl)+'</text>'; }
      h+='</g>';
    });
    svg.innerHTML=h; applyHL(!dragging);
  }
  // Acende só o item selecionado + relacionados; o resto esmaece. Em transição suave
  // (CSS) quando não está arrastando — aplica a opacidade num próximo frame.
  function applyHL(animate){
    var svg=document.getElementById('corr-svg'); if(!svg)return;
    var hl=sel?neighbors(sel):null;
    var nodes=svg.querySelectorAll('g.corr-node'), lines=svg.querySelectorAll('line');
    function go(){
      for(var i=0;i<nodes.length;i++){ var id=nodes[i].getAttribute('data-id'); nodes[i].style.opacity=hl?(hl[id]?1:0.05):1; }
      for(var k=0;k<lines.length;k++){ var ds=lines[k].getAttribute('data-s'),dt=lines[k].getAttribute('data-t'); lines[k].style.opacity=hl?((ds===sel||dt===sel)?1:0.04):1; }
    }
    if(animate&&hl) requestAnimationFrame(go); else go();
  }
  function render(camp){
    var rts=roots(camp); rts.forEach(function(r){ if(!(r in open)) open[r]=true; });
    _vis=visible(rts); _ids=Object.keys(_vis); layout(_ids,960,600); paint(); buildList();
  }
  function toSvg(cx,cy){ var svg=document.getElementById('corr-svg'); if(!svg||!svg.createSVGPoint)return null; var pt=svg.createSVGPoint(); pt.x=cx; pt.y=cy; var m=svg.getScreenCTM(); if(!m)return null; return pt.matrixTransform(m.inverse()); }
  function applyVB(){ var svg=document.getElementById('corr-svg'); if(svg)svg.setAttribute('viewBox',vb.x.toFixed(1)+' '+vb.y.toFixed(1)+' '+vb.w.toFixed(1)+' '+vb.h.toFixed(1)); }
  function clamp(v,a,b){ return Math.max(a,Math.min(b,v)); }
  // Alvo do zoom mantendo o ponto (mx,my) fixo. f<1 aproxima, f>1 afasta.
  function targetZoom(mx,my,f){ var nw=clamp(vb.w*f,140,2200), nh=nw*(600/960); return {x:mx-(mx-vb.x)*(nw/vb.w), y:my-(my-vb.y)*(nh/vb.h), w:nw, h:nh}; }
  function setVB(t){ vb.x=t.x;vb.y=t.y;vb.w=t.w;vb.h=t.h; applyVB(); }
  function tweenVB(to,ms){ var f={x:vb.x,y:vb.y,w:vb.w,h:vb.h}, t0=(window.performance&&performance.now)?performance.now():Date.now();
    function step(now){ var k=Math.min(1,((now||Date.now())-t0)/ms), e=k<0.5?2*k*k:1-Math.pow(-2*k+2,2)/2;
      vb.x=f.x+(to.x-f.x)*e; vb.y=f.y+(to.y-f.y)*e; vb.w=f.w+(to.w-f.w)*e; vb.h=f.h+(to.h-f.h)*e; applyVB(); if(k<1)requestAnimationFrame(step); }
    requestAnimationFrame(step); }
  function zoomAt(mx,my,f){ setVB(targetZoom(mx,my,f)); }   // instantâneo (roda/arraste)
  // Botões: k>0 APROXIMA (+), k<0 AFASTA (−), 'r' reajusta. Animado e suave (item 1 + 6).
  window.__corrZoom=function(k){ if(k==='r'){ tweenVB({x:0,y:0,w:960,h:600},230); } else { tweenVB(targetZoom(vb.x+vb.w/2,vb.y+vb.h/2,k>0?0.8:1.25),200); } };
  function bindDrag(){
    var svg=document.getElementById('corr-svg'); if(!svg||svg.__bound)return; svg.__bound=true; svg.style.touchAction='none'; svg.style.cursor='grab';
    svg.addEventListener('pointerdown',function(e){ var g=e.target.closest&&e.target.closest('g.corr-node[data-id]');
      if(g){ var id=g.getAttribute('data-id'); var p=toSvg(e.clientX,e.clientY); if(!p||!POS[id])return; drag=id; dragging=true; dragMoved=false; sx=p.x; sy=p.y; ox=p.x-POS[id].x; oy=p.y-POS[id].y; }
      else { pan={cx:e.clientX,cy:e.clientY,vx:vb.x,vy:vb.y,moved:false}; svg.style.cursor='grabbing'; }
      try{svg.setPointerCapture(e.pointerId);}catch(_){} e.preventDefault(); });
    svg.addEventListener('pointermove',function(e){
      if(drag){ var p=toSvg(e.clientX,e.clientY); if(!p)return; if(Math.abs(p.x-sx)>3||Math.abs(p.y-sy)>3)dragMoved=true; POS[drag].x=p.x-ox; POS[drag].y=p.y-oy; PIN[drag]=true; paint(); }
      else if(pan){ var rect=svg.getBoundingClientRect(); var dx=e.clientX-pan.cx, dy=e.clientY-pan.cy; if(Math.abs(dx)>3||Math.abs(dy)>3)pan.moved=true; vb.x=pan.vx-dx*(vb.w/rect.width); vb.y=pan.vy-dy*(vb.h/rect.height); applyVB(); } });
    function end(){ if(drag){ var id=drag; drag=null; dragging=false; if(!dragMoved) selectNode(id); else applyHL(false); }
      else if(pan){ var pm=pan.moved; pan=null; svg.style.cursor='grab'; if(!pm && sel){ sel=null; selRoots=null; hideDetail(); render(curCamp()); } } }
    svg.addEventListener('pointerup',end); svg.addEventListener('pointercancel',end);
    svg.addEventListener('wheel',function(e){ e.preventDefault(); var p=toSvg(e.clientX,e.clientY); if(!p)return; zoomAt(p.x,p.y,e.deltaY<0?0.85:1.176); },{passive:false});
  }
  // Clicar liga e destaca o item + TODOS os relacionados (vale nos dois sentidos e nas duas visões):
  //  · subdomínio  → mostra o IP que ele resolve;  · IP → mostra todos os subdomínios que resolvem nele.
  function selectNode(id){ var n=N[id]; if(!n)return; if(kids(id))open[id]=!open[id]; sel=id;
    var rel=neighbors(id); selRoots={};
    Object.keys(rel).forEach(function(rid){ revealAncestors(rid); rootsOf(rid).forEach(function(rt){selRoots[rt]=1;});
      if(rid!==id && (ADJ[rid]||[]).indexOf(id)>=0) open[rid]=true; });  // pai de id: abre p/ garantir id visível
    rootsOf(id).forEach(function(rt){selRoots[rt]=1;});
    render(curCamp()); detail(id);
  }
  function detail(id){ var n=N[id],d=document.getElementById('corr-detail'); if(!d)return;
    var rows=(n.detail||[]).map(function(kv){ return '<tr><td style="color:var(--muted);padding:5px 12px 5px 0;white-space:nowrap;vertical-align:top">'+esc(kv[0])+'</td><td style="padding:5px 0;text-align:right">'+esc(kv[1])+'</td></tr>'; }).join('');
    var sh=isShared(id);
    d.innerHTML='<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px"><span style="width:12px;height:12px;border-radius:50%;background:'+(SEV[n.risk]||'#8a99b4')+';flex:none"></span><span style="font-size:15px;font-weight:700">'+esc(n.label)+'</span>'+(sh?' <span style="color:#fb923c;font-size:12px">(compartilhado · '+degOf(id)+' subdomínios)</span>':'')+'</div>'
      +'<div class="page-sub" style="margin-bottom:10px">'+esc(TLBL[n.type]||n.type)+(kids(id)?(' · clique no nó para '+(open[id]?'recolher':'expandir')):'')+'</div>'
      +'<table style="width:100%;font-size:13px;border-top:1px solid var(--border)">'+rows+'</table>';
    d.style.display='block';
  }
  function buildList(){ var el=document.getElementById('corr-list'); if(!el)return;
    var subs=Object.keys(N).filter(function(id){return N[id].type==='subdomain';});
    var html='<table><caption class="sr-only">Subdomínios e seus IPs; "compartilhado por" indica IP servindo vários subdomínios</caption><thead><tr><th scope="col">Subdomínio</th><th scope="col">IP</th><th scope="col">Compartilhado por</th><th scope="col">Risco</th></tr></thead><tbody>';
    subs.sort(function(a,b){return N[a].label.localeCompare(N[b].label);}).forEach(function(id){
      var ipid=(ADJ[id]||[]).filter(function(c){return N[c]&&N[c].type==='ip';})[0] || parentsOf(id).filter(function(c){return N[c]&&N[c].type==='ip';})[0];
      var ipn=ipid?N[ipid]:null, deg=ipid?degOf(ipid):1;
      html+='<tr><td>'+esc(N[id].label)+'</td><td>'+(ipn?'<code>'+esc(ipn.label)+'</code>':'—')+'</td><td>'+(deg>1?('<span style="color:#fb923c;font-weight:700">'+deg+' subdomínios</span>'):'1')+'</td><td class="risk-'+esc(N[id].risk)+'">'+esc(N[id].risk)+'</td></tr>';
    });
    html+='</tbody></table>'; el.innerHTML=html;
  }
  document.addEventListener('keydown',function(e){ if(e.key!=='Enter'&&e.key!==' ')return; var g=e.target.closest&&e.target.closest('g.corr-node[data-id]'); if(g){e.preventDefault();selectNode(g.getAttribute('data-id'));} });
  if(document.readyState!=='loading') start(); else document.addEventListener('DOMContentLoaded',start);
})();
</script>"""


def build_correlation_page() -> str:
    body = (
        '<style>'
        '#corr-wrap{border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);overflow:auto;margin-top:6px}'
        '#corr-svg{width:100%;height:600px;display:block}'
        # Transições suaves (opacidade) + leve sombra = sensação de profundidade ao destacar/recuar (item 6).
        '.corr-node{cursor:pointer;transition:opacity .28s ease;filter:drop-shadow(0 1px 1.5px rgba(0,0,0,.55))}'
        '#corr-svg line{transition:opacity .28s ease}'
        '.corr-node:hover circle{stroke-width:3}'
        '.corr-node:focus{outline:none}.corr-node:focus circle{stroke:var(--accent);stroke-width:3}'
        '#corr-detail{display:none;margin-top:14px}'
        '.corr-legend{display:flex;gap:16px;flex-wrap:wrap;align-items:center;font-size:12px;color:var(--muted);margin-left:auto}'
        '.corr-legend .dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:5px;vertical-align:middle}'
        # Botões do filtro de severidade (item 2): cada um é um "pílula" que liga/desliga o nível.
        '.sevbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:2px 0 12px}'
        '.sevbtn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);background:var(--surface-2);'
        'color:var(--text);font-size:12px;font-weight:600;padding:4px 10px;border-radius:999px;cursor:pointer;transition:opacity .15s,filter .15s}'
        '.sevbtn .dot{width:9px;height:9px;border-radius:50%;display:inline-block}'
        '.sevbtn.off{opacity:.4;filter:grayscale(.7)}'
        '.sevbtn.off .dot{background:var(--muted)!important}'
        '</style>'
        # Estado vazio (mesmo padrão dos módulos): nenhum achado para correlacionar ainda.
        '<div id="corr-empty" class="panel panel-pad" style="display:none;text-align:center;padding:40px 24px">'
        '<div style="font-weight:700;font-size:15px;color:var(--text);margin-bottom:6px">Nada para correlacionar ainda</div>'
        '<div style="color:var(--muted);font-size:13px;line-height:1.6;max-width:580px;margin:0 auto">O mapa cruza '
        '<b>tudo o que foi descoberto</b> — subdomínios, IPs/portas, reputação, CVE/KEV/CVSS, postura de e-mail, '
        'credenciais vazadas e domínios sósia. Rode os scanners (<code>sudo argus-submonitor</code>, '
        '<code>sudo argus-monitor --tcp</code>, etc.) — o grafo aparece aqui em seguida.</div>'
        '<div style="margin-top:16px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap">'
        '<a class="btn btn-pdf" href="/dashboard.html" style="text-decoration:none">Ver o Dashboard</a></div></div>'
        # Serviço web indisponível (este módulo depende do argus-web para juntar os bancos).
        '<div id="corr-off" class="panel panel-pad" style="display:none;text-align:center;padding:40px 24px">'
        '<div style="font-weight:700;font-size:15px;color:var(--text);margin-bottom:6px">Serviço de correlação indisponível</div>'
        '<div style="color:var(--muted);font-size:13px;line-height:1.6;max-width:560px;margin:0 auto">Este mapa é montado '
        'pelo serviço <code>argus-web</code> (junta os bancos dos scanners em tempo real). '
        'Verifique se o serviço está ativo: <code>systemctl status argus-web</code>.</div></div>'
        # Conteúdo principal (escondido até carregar)
        '<div id="corr-main" style="display:none">'
        '<div class="toolbar no-print">'
        '<select id="corr-camp" aria-label="Filtrar por campanha"></select>'
        # Seletor de VISÃO (item 3): organiza o grafo por subdomínio ou por IP.
        '<select id="corr-view" aria-label="Organização do grafo" title="Como o grafo é organizado">'
        '<option value="sub">Por subdomínio (campanha → domínio → subdomínio → IP)</option>'
        '<option value="ip">Por IP (campanha → domínio → IP → subdomínios)</option>'
        '</select>'
        '<div class="corr-legend">'
        '<span>cor = criticidade:</span>'
        '<span><span class="dot" style="background:#f43f5e"></span>crítico</span>'
        '<span><span class="dot" style="background:#fb923c"></span>alto</span>'
        '<span><span class="dot" style="background:#fbbf24"></span>médio</span>'
        '<span><span class="dot" style="background:#34d399"></span>baixo</span>'
        '<span><span class="dot" style="background:#8a99b4"></span>info</span>'
        '<span style="color:#fb923c">&#9711; anel = IP compartilhado</span></div></div>'
        # Legenda de FORMAS por tipo (a cor já indica criticidade).
        '<div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center;font-size:12px;color:var(--muted);margin:2px 0 10px">'
        '<span>forma = tipo:</span>'
        '<span style="color:var(--steel-2)"><svg width="13" height="13" viewBox="0 0 14 14" style="vertical-align:-2px"><circle cx="7" cy="7" r="5.5" fill="currentColor"/></svg> esfera = campanha/domínio/subdomínio</span>'
        '<span style="color:var(--steel-2)"><svg width="13" height="13" viewBox="0 0 14 14" style="vertical-align:-2px"><polygon points="7,1 13,7 7,13 1,7" fill="currentColor"/></svg> losango = IP</span>'
        '<span style="color:var(--steel-2)"><svg width="13" height="13" viewBox="0 0 14 14" style="vertical-align:-2px"><polygon points="7,1.5 13,12 1,12" fill="currentColor"/></svg> triângulo = e-mail</span>'
        '<span style="color:var(--steel-2)"><svg width="13" height="13" viewBox="0 0 14 14" style="vertical-align:-2px"><rect x="2" y="2" width="10" height="10" rx="1.5" fill="currentColor"/></svg> quadrado = credenciais</span>'
        '<span style="color:var(--steel-2)"><svg width="13" height="13" viewBox="0 0 14 14" style="vertical-align:-2px"><polygon points="7,1 12.2,4 12.2,10 7,13 1.8,10 1.8,4" fill="currentColor"/></svg> hexágono = typosquat</span>'
        '</div>'
        # Filtro de severidade (item 2): clique para mostrar SÓ os níveis ligados.
        '<div class="sevbar" role="group" aria-label="Filtrar por criticidade">'
        '<span style="font-size:12px;color:var(--muted)">mostrar:</span>'
        '<button class="sevbtn" id="sevb-CRITICO" type="button" aria-pressed="true" onclick="window.__corrSev&&window.__corrSev(\'CRITICO\')"><span class="dot" style="background:#f43f5e"></span>crítico</button>'
        '<button class="sevbtn" id="sevb-ALTO" type="button" aria-pressed="true" onclick="window.__corrSev&&window.__corrSev(\'ALTO\')"><span class="dot" style="background:#fb923c"></span>alto</button>'
        '<button class="sevbtn" id="sevb-MEDIO" type="button" aria-pressed="true" onclick="window.__corrSev&&window.__corrSev(\'MEDIO\')"><span class="dot" style="background:#fbbf24"></span>médio</button>'
        '<button class="sevbtn" id="sevb-BAIXO" type="button" aria-pressed="true" onclick="window.__corrSev&&window.__corrSev(\'BAIXO\')"><span class="dot" style="background:#34d399"></span>baixo</button>'
        '<button class="sevbtn" id="sevb-INFO" type="button" aria-pressed="true" onclick="window.__corrSev&&window.__corrSev(\'INFO\')"><span class="dot" style="background:#8a99b4"></span>info</button>'
        '<button class="btn btn-clr" type="button" style="margin-left:4px" onclick="window.__corrSev&&window.__corrSev(\'all\')" title="Mostrar todos os níveis">tudo</button>'
        '</div>'
        '<div class="kpi-grid" style="max-width:540px;margin-bottom:14px">'
        '<div class="kpi"><div class="v" id="corr-nsub">&mdash;</div><div class="l">Subdomínios</div></div>'
        '<div class="kpi"><div class="v" id="corr-nip">&mdash;</div><div class="l">IPs únicos</div></div>'
        '<div class="kpi sev-abus"><div class="v" id="corr-nshared">&mdash;</div><div class="l">IPs compartilhados</div></div></div>'
        # Controles de zoom (a roda do mouse também dá zoom; arrastar o fundo faz pan).
        '<div style="display:flex;gap:6px;align-items:center;margin-bottom:6px">'
        '<button class="btn btn-clr" type="button" onclick="window.__corrZoom&&window.__corrZoom(1)" aria-label="Aproximar" title="Aproximar (zoom +)">&#x2795;</button>'
        '<button class="btn btn-clr" type="button" onclick="window.__corrZoom&&window.__corrZoom(-1)" aria-label="Afastar" title="Afastar (zoom -)">&#x2796;</button>'
        '<button class="btn btn-clr" type="button" onclick="window.__corrZoom&&window.__corrZoom(\'r\')" aria-label="Reajustar zoom" title="Reajustar (100%)">&#x21BB; ajustar</button>'
        '<span class="page-sub" style="margin:0 0 0 4px">roda = zoom · arraste o fundo = mover</span></div>'
        '<div id="corr-wrap"><svg id="corr-svg" viewBox="0 0 960 600" role="img" '
        'aria-label="Grafo de correlação entre campanhas, subdomínios e IPs. Use a lista acessível abaixo para os detalhes."></svg></div>'
        '<p class="page-sub" style="margin-top:8px">Clique em um nó para <b>expandir</b> e <b>destacar</b> só ele e os '
        'relacionados (o resto esmaece); clique no fundo para limpar. Ao clicar num <b>subdomínio</b> ele acende o '
        '<b>IP</b> que resolve; ao clicar num <b>IP</b>, acende <b>todos os subdomínios</b> que caem nele. Use a caixa '
        '<b>“Por IP”</b> para inverter o grafo e ver de cara quais IPs concentram mais subdomínios (infra crítica), e os '
        'botões <b>de criticidade</b> para mostrar só os níveis que importam. <b>Arraste</b> os nós, use a '
        '<b>roda</b>/<b>+ −</b> para <b>zoom</b>. Anel pontilhado = pode expandir; IP com anel '
        '<span style="color:#fb923c">laranja</span> é servido por vários subdomínios (raio de explosão).</p>'
        '<div id="corr-detail" class="panel panel-pad"></div>'
        '<details style="margin-top:14px"><summary style="cursor:pointer;color:var(--muted);font-weight:600">'
        'Lista acessível (subdomínio &rarr; IP)</summary>'
        '<div id="corr-list" class="tbl-wrap" style="margin-top:10px"></div></details>'
        '</div>'
    )
    return _portal_shell(
        "correlacao", "Correlação",
        "Mapa de toda a superfície: domínios, subdomínios, IPs e achados (e-mail, credenciais, typosquat) — "
        "com enriquecimento e cor por criticidade",
        body, extra_script=_CORR_SCRIPT)


def build_login_page() -> str:
    """Página de login com a identidade Argus (form-based, para o Apache
    `mod_auth_form`). É **self-contained** (CSS inline) e PÚBLICA — precisa ser
    alcançável sem sessão. O formulário posta `httpd_username`/`httpd_password`
    para o handler `/dologin`: a credencial é validada **no Apache**, o app NÃO
    guarda nem recebe a senha. Mensagens de erro/logout vêm por query param."""
    css = _common_css()
    login_css = (
        " body.login-body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}"
        " .login-card{width:100%;max-width:380px;background:linear-gradient(180deg,var(--surface),var(--surface-2));"
        "border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:30px 28px 26px}"
        " .login-head{text-align:center;margin-bottom:6px}"
        " .login-head .logo{width:64px;height:64px;filter:drop-shadow(0 0 18px rgba(51,163,239,.34))}"
        " .login-head .wordmark{font-size:30px;letter-spacing:6px;margin-top:10px}"
        " .login-head .sub{color:var(--accent);font-size:10px;font-weight:700;letter-spacing:3px;"
        "text-transform:uppercase;margin-top:5px}"
        " .login-form label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;"
        "color:var(--muted);margin:14px 0 5px}"
        " .login-form input{width:100%;background:var(--surface);border:1px solid var(--border);"
        "border-radius:var(--radius-sm);color:var(--text);padding:11px 12px;font-size:14px;outline:none}"
        " .login-form input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(51,163,239,.12)}"
        " .login-btn{width:100%;margin-top:20px;padding:12px;border:none;border-radius:var(--radius-sm);"
        "background:linear-gradient(180deg,var(--accent),#2b85db);color:#04121f;font-size:14px;font-weight:800;"
        "letter-spacing:.4px;cursor:pointer;transition:.15s}"
        " .login-btn:hover{filter:brightness(1.07);transform:translateY(-1px)}"
        " .login-msg{margin-top:14px;font-size:12.5px;text-align:center;display:none;padding:8px 10px;"
        "border-radius:var(--radius-sm)}"
        " .login-msg.err{display:block;color:#fda4af;background:rgba(244,63,94,.16);border:1px solid rgba(244,63,94,.4)}"
        " .login-msg.ok{display:block;color:#6ee7b7;background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.3)}"
        " body.light .login-msg.err{color:#be123c} body.light .login-msg.ok{color:#047857}"
        " .login-foot{margin-top:18px;text-align:center;color:var(--faint);font-size:11px}"
        " .login-theme{position:fixed;top:16px;right:16px}"
    )
    moon = ('<svg class="ic-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>')
    sun = ('<svg class="ic-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
           'stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/>'
           '<path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41'
           'M19.07 4.93l-1.41 1.41M6.34 17.66l-1.41 1.41"/></svg>')
    init_js = ("(function(){try{if(localStorage.getItem('argus-theme')==='light')"
               "document.body.classList.add('light');}catch(e){}})();"
               "function argusToggleTheme(){var l=document.body.classList.toggle('light');"
               "try{localStorage.setItem('argus-theme',l?'light':'dark');}catch(e){}}")
    msg_js = ("(function(){var q=new URLSearchParams(location.search),m=document.getElementById('msg');"
              "if(q.has('error')){m.textContent='Usuário ou senha inválidos.';m.className='login-msg err';}"
              "else if(q.has('logout')){m.textContent='Sessão encerrada com segurança.';m.className='login-msg ok';}})();")
    return (
        '<!DOCTYPE html>\n<html lang="pt-BR">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<title>Entrar — Argus</title>\n'
        f'<link rel="icon" type="image/svg+xml" href="{_FAVICON}">\n'
        f'<style>{css}{login_css}</style>\n'
        '</head>\n<body class="login-body">\n'
        f'<script>{init_js}</script>\n'
        '<button class="theme-toggle login-theme" type="button" onclick="argusToggleTheme()" '
        'title="Tema claro/escuro" aria-label="Alternar tema">' + moon + sun + '</button>\n'
        '<div class="login-card">\n'
        '  <div class="login-head">\n    ' + _logo_svg(64) + '\n'
        '    <div class="wordmark">ARGUS</div>\n'
        '    <div class="sub">Attack Surface Management</div>\n'
        '  </div>\n'
        '  <form class="login-form" method="POST" action="/dologin" autocomplete="on">\n'
        '    <label for="u">Usuário</label>\n'
        '    <input id="u" name="httpd_username" type="text" autocomplete="username" autofocus required>\n'
        '    <label for="p">Senha</label>\n'
        '    <input id="p" name="httpd_password" type="password" autocomplete="current-password" required>\n'
        '    <button class="login-btn" type="submit">Entrar</button>\n'
        '  </form>\n'
        '  <div id="msg" class="login-msg"></div>\n'
        '  <div class="login-foot">Acesso restrito · sessão protegida (TLS)</div>\n'
        '</div>\n'
        f'<script>{msg_js}</script>\n'
        '</body>\n</html>\n'
    )


def _empty_state(active: str, label: str) -> str:
    """Estado vazio pedagógico (onboarding) — mostrado enquanto o módulo não rodou.
    Diferencia por scanner: agenda do próximo scan, comando manual e próximos passos."""
    # (comando, agenda legível) por módulo — alinhado aos cron jobs do install.
    meta = {
        "monitor":     ("argus-monitor",     "diariamente às 10:00 (UDP aos domingos às 03:00)"),
        "submonitor":  ("argus-submonitor",  "diariamente às 12:00"),
        "credentials": ("argus-credentials", "diariamente às 14:00"),
        "email":       ("argus-email",       "diariamente às 13:00"),
        "typosquat":   ("argus-typosquat",   "aos domingos às 05:00"),
        "findings":    ("",                   "atualizado a cada execução de qualquer scanner"),
    }
    cmd, sched = meta.get(active, ("", ""))
    icon = _NAV_ICONS.get(active, "")
    run_block = (
        '<div style="margin-top:14px"><div style="font-size:12px;color:var(--muted);margin-bottom:6px">'
        'Quer ver agora, sem esperar o agendamento? Rode no servidor:</div>'
        f'<pre style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;'
        f'font-size:12.5px;color:var(--steel);display:inline-block">sudo {cmd}</pre></div>'
    ) if cmd else ""
    return (
        '<div class="panel panel-pad" style="text-align:center;padding:40px 24px">'
        f'<div style="width:56px;height:56px;margin:0 auto 14px;border-radius:14px;display:grid;place-items:center;'
        f'background:rgba(51,163,239,.12);color:var(--accent)">{icon}</div>'
        f'<h2 style="font-size:17px;color:var(--text);margin-bottom:8px">Aguardando a primeira execução</h2>'
        '<p style="color:var(--muted);font-size:13.5px;max-width:560px;margin:0 auto;line-height:1.6">'
        f'Este módulo (<b>{label}</b>) ainda não coletou dados. O scan roda <b>{sched}</b> — '
        'os resultados aparecem aqui automaticamente na sequência. Não é erro nem configuração pendente: '
        'é só a primeira coleta que ainda não ocorreu.</p>'
        + run_block +
        '<div style="margin-top:18px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap">'
        '<a class="btn btn-pdf" href="/dashboard.html" style="text-decoration:none">Ver o Dashboard</a>'
        '<a class="btn btn-clr" href="/risk-guide.html" style="text-decoration:none">Como o risco é classificado</a>'
        '</div></div>'
    )


def write_portal(docroot: str) -> None:
    """Grava app.css + login + index/dashboard/risk-guide e placeholders dos relatórios."""
    d = Path(docroot)
    assets = d / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    (assets / "app.css").write_text(app_css(), encoding="utf-8")
    (d / "login.html").write_text(build_login_page(), encoding="utf-8")
    (d / "index.html").write_text(build_index(), encoding="utf-8")
    (d / "dashboard.html").write_text(build_dashboard(), encoding="utf-8")
    (d / "risk-guide.html").write_text(build_risk_guide(), encoding="utf-8")
    # Página de Correlação — lê os relatórios client-side; sempre regerada.
    (d / "correlacao.html").write_text(build_correlation_page(), encoding="utf-8")
    for name, active, label in [
        ("findings_report.html",    "findings",    "Gestão de Achados"),
        ("monitor_report.html",     "monitor",     "Monitor de Portas"),
        ("submonitor_report.html",  "submonitor",  "Monitor de Subdomínios"),
        ("credentials_report.html", "credentials", "Exposição de Credenciais"),
        ("email_report.html",       "email",       "Postura de E-mail"),
        ("typosquat_report.html",   "typosquat",   "Typosquat"),
    ]:
        p = d / name
        if not p.exists():
            p.write_text(_portal_shell(
                active, label, "Aguardando a primeira execução do scan",
                _empty_state(active, label)),
                encoding="utf-8")
