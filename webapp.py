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

try:
    from flask import Flask, request, jsonify
    _FLASK_OK = True
except ImportError:                       # degrada com mensagem clara
    _FLASK_OK = False

import findings as F

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


def _regen_page():
    """Regenera a página estática de achados após uma ação (best-effort)."""
    try:
        import reporter
        reporter.write_findings_page(DOCROOT)
    except Exception:
        pass


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
            return jsonify(ok=False, error="CSRF: header ausente"), 403
        data = request.get_json(silent=True) or {}
        to = F.normalize_status(str(data.get("status", "")))
        if not to:
            return jsonify(ok=False, error="status inválido"), 400
        note = (str(data.get("note", "")) or "")[:_MAX_NOTE] or None
        repo, rid = _resolve(fid)
        if rid == "ambiguous":
            return jsonify(ok=False, error="prefixo ambíguo"), 400
        try:
            if not rid:
                return jsonify(ok=False, error="não encontrado"), 404
            repo.set_status(rid, to, actor=_actor(request), note=note)
            f = repo.get(rid)
        finally:
            if repo: repo.close()
        _regen_page()
        return jsonify(ok=True, id=rid, status=to, status_label=F.STATUS_LABEL.get(to, to))

    @app.post("/api/findings/<fid>/note")
    def add_note(fid):
        if not _csrf_ok():
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
        _regen_page()
        return jsonify(ok=True, id=rid)

    @app.post("/api/findings/<fid>/evidence")
    def add_evidence(fid):
        if not _csrf_ok():
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
        _regen_page()
        return jsonify(ok=True, id=rid)

    return app


app = create_app() if _FLASK_OK else None


if __name__ == "__main__":
    if not _FLASK_OK:
        raise SystemExit("[ERRO] Flask não instalado — instale com: pip install flask")
    print(f"[ARGUS] API de achados em http://{BIND_HOST}:{BIND_PORT} (store: {F.default_db_path()})")
    app.run(host=BIND_HOST, port=BIND_PORT)
