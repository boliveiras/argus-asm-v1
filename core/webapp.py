#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Argus ASM — monitoramento de superfície de ataque
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
webapp.py — Backend mínimo (Flask) para AÇÕES de gestão de achados na Web
=========================================================================

API REST pequena que expõe o `FindingRepository` para a interface Web tratar
achados (mudar status, anexar nota/evidência, marcar falso-positivo). É o
componente server-side da Fase 2.1; a página de Gestão de Achados continua sendo
HTML estático (gerado pelo reporter), e este serviço apenas processa as AÇÕES.

Postura de segurança (defesa em profundidade):
  • Bind em 127.0.0.1 — NUNCA exposto direto; o Apache (TLS + Basic Auth, :8443)
    é o único front-door, via reverse-proxy.
  • Autenticação é do Apache; o usuário autenticado chega no header X-Remote-User
    e vira o `actor` da auditoria (rastreabilidade ISO 27001/CIS).
  • Mitigação CSRF: ações (POST) exigem o header X-Requested-With: argus (enviado
    pelo JS da página same-origin), além de só aceitarem JSON.
  • Toda ação é auditada (finding_events) pelo próprio domínio.
  • Após cada ação, a página estática é regenerada (reflete a mudança na hora).

Endpoints:
  GET  /api/health
  GET  /api/findings                 (lista/snapshot — leitura)
  GET  /api/findings/<id>            (detalhe + histórico + notas + evidências)
  POST /api/findings/<id>/status     {status, note?}
  POST /api/findings/<id>/note       {note}
  POST /api/findings/<id>/evidence   {label, ref}

Execução (dev): python3 webapp.py    → http://127.0.0.1:8099
Produção: serviço systemd como o app user, atrás do Apache (Fase 2.1b).
"""

import os
import sqlite3
from pathlib import Path

try:
    from flask import Flask, request, jsonify
    _FLASK_OK = True
except ImportError:                       # degrada com mensagem clara
    _FLASK_OK = False

import findings as F


# ============================================================
# CORRELAÇÃO — grafo da superfície (junta os bancos dos scanners)
# ============================================================

_RANK = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}
_ACTIVE = "('NOVO','REINCIDENTE','RESSURGIDO')"


def _argus_base() -> str:
    """Diretório base do Argus (/etc/argus). Deriva do ARGUS_DB, senão usa o padrão."""
    db = os.environ.get("ARGUS_DB", "")
    if db:
        p = Path(db).resolve().parent
        return str(p.parent if p.name == "store" else p)
    return os.environ.get("ARGUS_BASE", "/etc/argus")


def _worse(a: str, b: str) -> str:
    """Retorna a pior severidade entre as duas (para agregar campanha/domínio)."""
    return a if _RANK.get(a, 4) <= _RANK.get(b, 4) else b


def _ro_rows(db_path: str, sql: str) -> list[dict]:
    """Lê linhas de um banco em modo SOMENTE LEITURA. Nunca levanta."""
    try:
        if not Path(db_path).exists():
            return []
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        try:
            cur = conn.execute(sql)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception:
        return []


def _base_domain(host: str, known: set) -> str:
    """Domínio-base de um hostname: o maior domínio conhecido que é sufixo dele;
    senão, heurística dos 2 últimos rótulos."""
    host = (host or "").lower().strip(".")
    cands = [d for d in known if host == d or host.endswith("." + d)]
    if cands:
        return max(cands, key=len)
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def correlation_graph(base: str | None = None) -> dict:
    """Constrói o grafo de correlação cruzando os bancos dos scanners + enriquecimento.
    Estrutura: campanha -> domínios -> (subdomínios + achados e-mail/credencial/typosquat)
    -> IPs (com ASN/reputação/portas/CVE/KEV/CVSS). Nunca levanta — bancos ausentes
    são simplesmente ignorados."""
    b = Path(base or _argus_base())
    subs = _ro_rows(str(b / "submonitor" / "submonitor.db"),
                    f"SELECT campanha,hostname,ip,asn,ip_type,environment,risk,http_status,ssl_status,origem "
                    f"FROM subdomains WHERE status IN {_ACTIVE}")
    mons = _ro_rows(str(b / "monitor" / "monitor.db"),
                    f"SELECT campanha,ip,port,protocol,service,asn,risk,abuse_score,abuse_country,abuse_isp,"
                    f"abuse_tor,idb_vuln_count,idb_vulns,kev_count,kev_cves,nvd_max_score,nvd_severity "
                    f"FROM scans WHERE status IN {_ACTIVE}")
    creds = _ro_rows(str(b / "credentials" / "credentials.db"),
                     f"SELECT campanha,domain,total,employees,users,third_parties,risk "
                     f"FROM domains WHERE status IN {_ACTIVE} AND total>0")
    mails = _ro_rows(str(b / "email" / "email.db"),
                     f"SELECT campanha,domain,spf_status,dmarc_status,dkim_status,risk,issues,has_mx "
                     f"FROM domains WHERE status IN {_ACTIVE}")
    typos = _ro_rows(str(b / "typosquat" / "typosquat.db"),
                     f"SELECT campanha,base_domain,domain,fuzzer,risk,whois_status,mx "
                     f"FROM lookalikes WHERE status IN {_ACTIVE}")

    # Agrega o enriquecimento por IP (vindo do monitor de portas).
    ipagg: dict[str, dict] = {}
    for r in mons:
        ip = (r.get("ip") or "").strip()
        if not ip:
            continue
        a = ipagg.setdefault(ip, {"ports": set(), "asn": "", "risk": "INFO", "cve": 0, "kev": 0,
                                  "cvss": 0.0, "abuse": -1, "country": "", "isp": "", "tor": 0,
                                  "kev_cves": set()})
        if r.get("port"):
            a["ports"].add(f"{r.get('port')}/{r.get('protocol') or 'tcp'}")
        a["asn"] = a["asn"] or (r.get("asn") or "")
        a["risk"] = _worse(a["risk"], r.get("risk") or "INFO")
        a["cve"] = max(a["cve"], int(r.get("idb_vuln_count") or 0))
        a["kev"] = max(a["kev"], int(r.get("kev_count") or 0))
        a["cvss"] = max(a["cvss"], float(r.get("nvd_max_score") or 0))
        for c in (r.get("kev_cves") or "").split(","):
            if c.strip():
                a["kev_cves"].add(c.strip())
        sc = r.get("abuse_score")
        if sc is not None and sc >= 0 and sc > a["abuse"]:
            a["abuse"] = int(sc); a["country"] = r.get("abuse_country") or ""
            a["isp"] = r.get("abuse_isp") or ""; a["tor"] = int(r.get("abuse_tor") or 0)

    # Domínios-base conhecidos (de credenciais/e-mail/typosquat) p/ ancorar subdomínios.
    known_domains = set()
    for r in creds:  known_domains.add((r.get("domain") or "").lower().strip("."))
    for r in mails:  known_domains.add((r.get("domain") or "").lower().strip("."))
    for r in typos:  known_domains.add((r.get("base_domain") or "").lower().strip("."))
    known_domains.discard("")

    nodes: dict[str, dict] = {}
    edges: list = []

    def node(nid, ntype, label, risk="INFO", detail=None):
        n = nodes.get(nid)
        if n is None:
            n = nodes[nid] = {"id": nid, "type": ntype, "label": label, "risk": risk,
                              "detail": detail or []}
        else:
            n["risk"] = _worse(n["risk"], risk)
        return n

    def edge(a, c):
        edges.append([a, c])

    def camp_node(camp):
        cid = "camp:" + camp
        node(cid, "campaign", camp, "INFO")
        return cid

    def dom_node(camp, dom):
        did = "dom:" + camp + ":" + dom
        node(did, "domain", dom, "INFO")
        edge(camp_node(camp), did)
        return did

    # ── Subdomínios -> IP (com enriquecimento do IP) ──
    for r in subs:
        camp = (r.get("campanha") or "").strip() or "(sem campanha)"
        host = (r.get("hostname") or "").strip()
        if not host:
            continue
        dom = _base_domain(host, known_domains)
        did = dom_node(camp, dom)
        sid = "sub:" + camp + ":" + host
        srisk = r.get("risk") or "INFO"
        node(sid, "subdomain", host, srisk, [
            ["Ambiente", r.get("environment") or "—"],
            ["HTTP", r.get("http_status") or "—"],
            ["SSL", r.get("ssl_status") or "—"],
            ["Origem", r.get("origem") or "—"],
            ["IP", r.get("ip") or "—"],
            ["ASN", r.get("asn") or "—"],
            ["Risco", srisk],
        ])
        node(did, "domain", dom, srisk)   # propaga severidade ao domínio/campanha
        node(camp_node(camp), "campaign", camp, srisk)
        edge(did, sid)
        ip = (r.get("ip") or "").strip()
        if ip:
            ag = ipagg.get(ip, {})
            iprisk = _worse(ag.get("risk", "INFO"), srisk)
            det = [["ASN", ag.get("asn") or r.get("asn") or "—"]]
            if ag.get("abuse", -1) >= 0:
                det.append(["Reputação (AbuseIPDB)",
                            f"{ag['abuse']}%" + (f" · {ag.get('isp')}" if ag.get("isp") else "")
                            + (" · TOR" if ag.get("tor") else "")])
            else:
                det.append(["Reputação (AbuseIPDB)", "sem dados"])
            det.append(["Portas abertas", ", ".join(sorted(ag.get("ports", []))) or "—"])
            det.append(["CVEs", str(ag.get("cve", 0)) + (f" · KEV {ag['kev']}" if ag.get("kev") else "")])
            if ag.get("cvss", 0):
                det.append(["CVSS máx", f"{ag['cvss']:.1f}"])
            det.append(["Tipo de IP", r.get("ip_type") or "—"])
            node("ip:" + ip, "ip", ip, iprisk, det)
            edge(sid, "ip:" + ip)

    # ── Achados de e-mail (por domínio) ──
    for r in mails:
        camp = (r.get("campanha") or "").strip() or "(sem campanha)"
        dom = (r.get("domain") or "").strip()
        if not dom:
            continue
        did = dom_node(camp, dom)
        risk = r.get("risk") or "INFO"
        eid = "email:" + camp + ":" + dom
        node(eid, "email", "postura de e-mail", risk, [
            ["SPF", r.get("spf_status") or "—"],
            ["DMARC", r.get("dmarc_status") or "—"],
            ["DKIM", r.get("dkim_status") or "—"],
            ["MX", "sim" if r.get("has_mx") else "não"],
            ["Problemas", r.get("issues") or "—"],
            ["Risco", risk],
        ])
        node(did, "domain", dom, risk)
        node(camp_node(camp), "campaign", camp, risk)
        edge(did, eid)

    # ── Achados de credenciais (por domínio) ──
    for r in creds:
        camp = (r.get("campanha") or "").strip() or "(sem campanha)"
        dom = (r.get("domain") or "").strip()
        if not dom:
            continue
        did = dom_node(camp, dom)
        risk = r.get("risk") or "INFO"
        cid = "cred:" + camp + ":" + dom
        node(cid, "cred", "credenciais vazadas", risk, [
            ["Total", str(r.get("total") or 0)],
            ["Funcionários", str(r.get("employees") or 0)],
            ["Usuários", str(r.get("users") or 0)],
            ["Terceiros", str(r.get("third_parties") or 0)],
            ["Risco", risk],
        ])
        node(did, "domain", dom, risk)
        node(camp_node(camp), "campaign", camp, risk)
        edge(did, cid)

    # ── Sósias (typosquat) por domínio-base ──
    for r in typos:
        camp = (r.get("campanha") or "").strip() or "(sem campanha)"
        base_d = (r.get("base_domain") or "").strip()
        look = (r.get("domain") or "").strip()
        if not base_d or not look:
            continue
        did = dom_node(camp, base_d)
        risk = r.get("risk") or "INFO"
        tid = "typo:" + camp + ":" + look
        node(tid, "typo", look, risk, [
            ["Base", base_d],
            ["Técnica", r.get("fuzzer") or "—"],
            ["Idade (domínio)", r.get("whois_status") or "—"],
            ["MX", "sim" if r.get("mx") else "não"],
            ["Risco", risk],
        ])
        node(did, "domain", base_d, risk)
        node(camp_node(camp), "campaign", camp, risk)
        edge(did, tid)

    # Detalhe sintético para campanhas e domínios (contagens).
    for n in nodes.values():
        if n["type"] == "campaign":
            doms = sum(1 for e in edges if e[0] == n["id"])
            n["detail"] = [["Domínios", str(doms)], ["Pior achado", n["risk"]]]
        elif n["type"] == "domain":
            ch = [e[1] for e in edges if e[0] == n["id"]]
            n["detail"] = [["Subdomínios", str(sum(1 for c in ch if c.startswith("sub:")))],
                           ["Achados", str(sum(1 for c in ch if c.split(':', 1)[0] in ('email', 'cred', 'typo')))],
                           ["Pior achado", n["risk"]]]

    ip_ids = [k for k in nodes if k.startswith("ip:")]
    indeg = {}
    for _a, c in edges:
        indeg[c] = indeg.get(c, 0) + 1
    shared = sum(1 for k in ip_ids if indeg.get(k, 0) > 1)
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {"campaigns": sum(1 for n in nodes.values() if n["type"] == "campaign"),
                  "subdomains": sum(1 for n in nodes.values() if n["type"] == "subdomain"),
                  "ips": len(ip_ids), "shared_ips": shared},
    }

try:
    import logs as _audit_log          # trilha de auditoria (RFC 5424, audit.log)
except Exception:                       # nunca impede a API de subir
    _audit_log = None

DOCROOT = os.environ.get("ARGUS_DOCROOT", "/var/www/argus")
BIND_HOST = os.environ.get("ARGUS_WEB_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("ARGUS_WEB_PORT", "8099"))

# Limites de tamanho de entrada (anti-abuso / higiene)
_MAX_NOTE = 2000
_MAX_REF  = 1000
_MAX_LBL  = 200


def _actor(request) -> str:
    """Usuário autenticado pelo Apache (rastreabilidade). Fallback seguro."""
    return (request.headers.get("X-Remote-User")
            or getattr(request, "remote_user", None)
            or "web")


def _client_ip(request) -> str:
    """IP real do cliente (a aplicação fica atrás do Apache → X-Forwarded-For)."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _audit(request, msgid, message="", *, outcome, action,
           obj="", object_type="", **extra) -> None:
    """Registra um evento na trilha de auditoria (best-effort, nunca levanta)."""
    if _audit_log is None:
        return
    try:
        _audit_log.audit(msgid, message, actor=_actor(request), src_ip=_client_ip(request),
                         action=action, object=obj, object_type=object_type, outcome=outcome,
                         user_agent=(request.headers.get("User-Agent", "") or "")[:200], **extra)
    except Exception:
        pass


def _regen_page() -> bool:
    """Regenera a página estática de achados após uma ação. Retorna True se
    conseguiu. Em caso de falha (ex.: sem permissão de escrita no docroot), LOGA
    (visível em journalctl -u argus-web) e retorna False — o dado já está no
    argus.db e a página é re-hidratada pela API no próximo carregamento."""
    try:
        import reporter
        reporter.write_findings_page(DOCROOT)
        return True
    except Exception as exc:
        import sys
        print(f"[argus-web] WARN: não foi possível regenerar {DOCROOT}/findings_report.html "
              f"({exc}). Verifique a permissão de escrita do docroot (pacote 'acl' + setfacl).",
              file=sys.stderr, flush=True)
        return False


def create_app():
    if not _FLASK_OK:
        raise RuntimeError("Flask não instalado — pip install flask")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024   # corpo pequeno

    def _csrf_ok() -> bool:
        return request.headers.get("X-Requested-With") == "argus"

    def _resolve(fid_or_prefix):
        repo = F.FindingRepository()
        try:
            return repo, repo.resolve_id(fid_or_prefix)
        except ValueError:
            repo.close()
            return None, "ambiguous"

    @app.get("/api/health")
    def health():
        try:
            counts = F.FindingRepository().counts()
            return jsonify(ok=True, store=F.default_db_path(), counts=counts)
        except Exception as exc:
            return jsonify(ok=False, error=str(exc)), 500

    @app.get("/api/findings")
    def list_findings():
        try:
            return jsonify(F.snapshot())
        except Exception as exc:
            return jsonify(ok=False, error=str(exc)), 500

    @app.get("/api/correlation")
    def correlation():
        try:
            g = correlation_graph()
            g["ok"] = True
            return jsonify(g)
        except Exception as exc:
            return jsonify(ok=False, error=str(exc)), 500

    @app.get("/api/findings/<fid>")
    def get_finding(fid):
        repo, rid = _resolve(fid)
        if rid == "ambiguous":
            return jsonify(ok=False, error="prefixo ambíguo"), 400
        try:
            if not rid:
                return jsonify(ok=False, error="não encontrado"), 404
            f = repo.get(rid)
            f["history"]  = repo.history(rid)
            f["notes_l"]  = repo.notes(rid)
            f["evidence_l"] = repo.evidence(rid)
            f["controls"] = F.controls_for(f.get("source", ""))
            return jsonify(ok=True, finding=f)
        finally:
            if repo: repo.close()

    @app.post("/api/findings/<fid>/status")
    def set_status(fid):
        if not _csrf_ok():
            _audit(request, "AUTHZ_DENY", "ação negada: header CSRF ausente",
                   outcome="deny", action="set_status")
            return jsonify(ok=False, error="CSRF: header ausente"), 403
        data = request.get_json(silent=True) or {}
        to = F.normalize_status(str(data.get("status", "")))
        if not to:
            return jsonify(ok=False, error="status inválido"), 400
        note = (str(data.get("note", "")) or "")[:_MAX_NOTE] or None
        repo, rid = _resolve(fid)
        if rid == "ambiguous":
            return jsonify(ok=False, error="prefixo ambíguo"), 400
        from_status = ""
        try:
            if not rid:
                return jsonify(ok=False, error="não encontrado"), 404
            from_status = (repo.get(rid) or {}).get("status", "")
            repo.set_status(rid, to, actor=_actor(request), note=note)
            f = repo.get(rid)
        finally:
            if repo: repo.close()
        regen = _regen_page()
        _audit(request, "FINDING_STATUS", f"status {from_status or '?'} -> {to}",
               outcome="success", action="set_status", obj=rid, object_type="finding",
               from_status=from_status, to_status=to)
        return jsonify(ok=True, id=rid, status=to, status_label=F.STATUS_LABEL.get(to, to),
                       regenerated=regen)

    @app.post("/api/findings/<fid>/note")
    def add_note(fid):
        if not _csrf_ok():
            _audit(request, "AUTHZ_DENY", "ação negada: header CSRF ausente",
                   outcome="deny", action="add_note")
            return jsonify(ok=False, error="CSRF: header ausente"), 403
        data = request.get_json(silent=True) or {}
        note = (str(data.get("note", "")).strip())[:_MAX_NOTE]
        if not note:
            return jsonify(ok=False, error="nota vazia"), 400
        repo, rid = _resolve(fid)
        if rid == "ambiguous":
            return jsonify(ok=False, error="prefixo ambíguo"), 400
        try:
            if not rid:
                return jsonify(ok=False, error="não encontrado"), 404
            repo.add_note(rid, note, actor=_actor(request))
        finally:
            if repo: repo.close()
        regen = _regen_page()
        _audit(request, "FINDING_NOTE", "nota/tratativa adicionada", outcome="success",
               action="add_note", obj=rid, object_type="finding")
        return jsonify(ok=True, id=rid, regenerated=regen)

    @app.post("/api/findings/<fid>/evidence")
    def add_evidence(fid):
        if not _csrf_ok():
            _audit(request, "AUTHZ_DENY", "ação negada: header CSRF ausente",
                   outcome="deny", action="add_evidence")
            return jsonify(ok=False, error="CSRF: header ausente"), 403
        data = request.get_json(silent=True) or {}
        label = (str(data.get("label", "")).strip())[:_MAX_LBL]
        ref   = (str(data.get("ref", "")).strip())[:_MAX_REF]
        if not label or not ref:
            return jsonify(ok=False, error="label e ref obrigatórios"), 400
        repo, rid = _resolve(fid)
        if rid == "ambiguous":
            return jsonify(ok=False, error="prefixo ambíguo"), 400
        try:
            if not rid:
                return jsonify(ok=False, error="não encontrado"), 404
            repo.add_evidence(rid, label, ref, actor=_actor(request))
        finally:
            if repo: repo.close()
        regen = _regen_page()
        _audit(request, "FINDING_EVIDENCE", "evidência anexada", outcome="success",
               action="add_evidence", obj=rid, object_type="finding", detail=label)
        return jsonify(ok=True, id=rid, regenerated=regen)

    return app


app = create_app() if _FLASK_OK else None


if __name__ == "__main__":
    if not _FLASK_OK:
        raise SystemExit("[ERRO] Flask não instalado — instale com: pip install flask")
    print(f"[ARGUS] API de achados em http://{BIND_HOST}:{BIND_PORT} (store: {F.default_db_path()})")
    app.run(host=BIND_HOST, port=BIND_PORT)
