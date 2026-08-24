"""Senha inicial gerada pelo sistema + bloqueio até a troca.

A senha inicial é gerada pelo Argus (instalador ou criação de conta na Web) e
mostrada UMA vez. O que torna isso aceitável é o bloqueio: enquanto a marca
`must_change_password` existir, a conta não faz nada além de trocar a senha —
se a senha vazar antes da troca, não dá acesso aos achados.
"""

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.modules.setdefault("nmap", types.ModuleType("nmap"))
sys.path.insert(0, "core")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        (base / "store").mkdir(parents=True, exist_ok=True)
        self.htpasswd = base / ".htpasswd-monitor"
        self.htpasswd.write_text("", encoding="utf-8")
        os.environ["ARGUS_BASE"] = self.tmp.name
        os.environ["ARGUS_DB"] = str(base / "store" / "argus.db")
        os.environ["ARGUS_HTPASSWD"] = str(self.htpasswd)
        os.environ["ARGUS_ADMIN_USER"] = "monitor"
        import users
        self.U = users

    def tearDown(self):
        for var in ("ARGUS_DB", "ARGUS_HTPASSWD", "ARGUS_ADMIN_USER"):
            os.environ.pop(var, None)
        self.tmp.cleanup()


# ── Geração da senha ─────────────────────────────────────────────────────────

class TestSenhaGerada(Base):
    def test_forte_e_do_alfabeto_sem_ambiguos(self):
        pw = self.U.generate_password()
        self.assertGreaterEqual(len(pw), 16)
        for char in pw:
            self.assertIn(char, self.U.PASSWORD_ALPHABET)
        # 0/O e 1/l/I se confundem na tela — o operador copia da saída do
        # instalador, e um caractere ambíguo vira "senha errada".
        self.assertFalse(set(pw) & set("0O1lI"))

    def test_nao_repete(self):
        senhas = {self.U.generate_password() for _ in range(50)}
        self.assertEqual(len(senhas), 50)

    def test_passa_na_validacao_de_senha(self):
        # Não adianta gerar uma senha que o próprio domínio recusaria.
        self.assertGreaterEqual(len(self.U.generate_password()), self.U.MIN_PASSWORD)


# ── Marca de troca obrigatória ───────────────────────────────────────────────

class TestMarca(Base):
    def test_conta_nova_marcada_precisa_trocar(self):
        self.U.create_user("ana", "senha-inicial-1", "user", must_change=True)
        self.assertTrue(self.U.must_change_password("ana"))

    def test_conta_nova_sem_marca_nao_precisa(self):
        self.U.create_user("bob", "senha-inicial-1", "user")
        self.assertFalse(self.U.must_change_password("bob"))

    def test_usuario_inexistente_nao_esta_marcado(self):
        self.assertFalse(self.U.must_change_password("ninguem"))
        self.assertFalse(self.U.must_change_password(""))

    def test_trocar_a_senha_limpa_a_marca(self):
        self.U.create_user("ana", "senha-inicial-1", "user", must_change=True)
        self.U.change_own_password("ana", "senha-inicial-1", "outra-senha-9")
        self.assertFalse(self.U.must_change_password("ana"))

    def test_troca_recusada_mantem_a_marca(self):
        self.U.create_user("ana", "senha-inicial-1", "user", must_change=True)
        with self.assertRaises(self.U.UserError):
            self.U.change_own_password("ana", "senha-errada", "outra-senha-9")
        self.assertTrue(self.U.must_change_password("ana"))

    def test_marca_nao_apaga_o_perfil(self):
        self.U.create_user("ana", "senha-inicial-1", "master", must_change=True)
        self.U.change_own_password("ana", "senha-inicial-1", "outra-senha-9")
        self.assertEqual(self.U.role_of("ana"), "master")

    def test_marcar_admin_da_instalacao(self):
        # O instalador marca a conta `monitor`, que não tem perfil em users.json.
        self.U.mark_must_change("monitor")
        self.assertTrue(self.U.must_change_password("monitor"))
        self.assertEqual(self.U.role_of("monitor"), self.U.ROLE_ADMIN)

    def test_listagem_mostra_quem_ainda_nao_trocou(self):
        self.U.create_user("ana", "senha-inicial-1", "user", must_change=True)
        self.U.create_user("bob", "senha-inicial-1", "user")
        por_nome = {u["name"]: u for u in self.U.list_users()}
        self.assertTrue(por_nome["ana"]["must_change_password"])
        self.assertFalse(por_nome["bob"]["must_change_password"])


# ── Bloqueio na API ──────────────────────────────────────────────────────────

class BaseWeb(Base):
    """Cliente Flask com um usuário `ana` marcado para trocar a senha."""

    def setUp(self):
        super().setUp()
        base = Path(self.tmp.name)
        alvos = base / "submonitor" / "targets"
        alvos.mkdir(parents=True, exist_ok=True)
        (alvos / "EMPRESA.txt").write_text("empresa.com\n", encoding="utf-8")
        (base / "submonitor" / "subs.txt").write_text("www\n", encoding="utf-8")
        self.U.create_user("ana", "senha-inicial-1", "master", must_change=True)
        self.U.create_user("bob", "senha-do-bob-1", "master")
        import webapp
        self.webapp = webapp
        self.app = webapp.create_app().test_client()
        self.MARCADO = {"X-Requested-With": "argus", "X-Remote-User": "ana"}
        self.LIVRE = {"X-Requested-With": "argus", "X-Remote-User": "bob"}


class TestBloqueioLeitura(BaseWeb):
    def test_leitura_de_achados_bloqueada(self):
        # O dado sensível é o achado. Se o guard só cobrisse POST, quem entra com
        # a senha inicial não mudaria nada — mas leria a superfície inteira.
        r = self.app.get("/api/findings", headers=self.MARCADO)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.get_json()["must_change_password"])

    def test_leitura_de_campanhas_bloqueada(self):
        r = self.app.get("/api/campaigns?scope=submonitor", headers=self.MARCADO)
        self.assertEqual(r.status_code, 403)

    def test_health_bloqueado_porque_conta_achados(self):
        # /api/health devolve a contagem de achados — é dado da superfície.
        r = self.app.get("/api/health", headers=self.MARCADO)
        self.assertEqual(r.status_code, 403)

    def test_sem_a_marca_a_leitura_segue_liberada(self):
        r = self.app.get("/api/campaigns?scope=submonitor", headers=self.LIVRE)
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(self.app.get("/api/findings", headers=self.LIVRE).status_code, 403)


class TestBloqueioEscrita(BaseWeb):
    def test_escrita_bloqueada(self):
        r = self.app.post("/api/campaigns/submonitor/EMPRESA/prefixos",
                          headers=self.MARCADO, json={"prefixos": ["dev-"]})
        self.assertEqual(r.status_code, 403)

    def test_sem_a_marca_a_escrita_segue_liberada(self):
        r = self.app.post("/api/campaigns/submonitor/EMPRESA/prefixos",
                          headers=self.LIVRE, json={"prefixos": ["dev-"]})
        self.assertEqual(r.status_code, 200)


class TestRotasDeRecuperacao(BaseWeb):
    """Bloquear o caminho da própria troca trancaria a conta para sempre."""

    def test_api_me_responde(self):
        r = self.app.get("/api/me", headers=self.MARCADO)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["must_change_password"])

    def test_version_responde(self):
        self.assertEqual(self.app.get("/version", headers=self.MARCADO).status_code, 200)

    def test_troca_da_propria_senha_liberada_e_limpa_a_marca(self):
        r = self.app.post("/api/me/password", headers=self.MARCADO,
                          json={"current": "senha-inicial-1", "new": "senha-nova-99"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(self.U.must_change_password("ana"))

    def test_depois_da_troca_a_leitura_volta(self):
        self.app.post("/api/me/password", headers=self.MARCADO,
                      json={"current": "senha-inicial-1", "new": "senha-nova-99"})
        r = self.app.get("/api/campaigns?scope=submonitor", headers=self.MARCADO)
        self.assertEqual(r.status_code, 200)


# ── Criação de conta pela Web ────────────────────────────────────────────────

class _AuditFalso:
    """Captura o que iria para a trilha de auditoria."""

    def __init__(self):
        self.linhas = []

    def audit(self, msgid, message="", **fields):
        self.linhas.append(msgid + " " + str(message) + " " + repr(fields))


class TestCriacaoPelaWeb(BaseWeb):
    def setUp(self):
        super().setUp()
        self.ADMIN = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}

    def test_conta_nasce_com_senha_gerada_e_marcada(self):
        r = self.app.post("/api/users", headers=self.ADMIN,
                          json={"name": "carla", "role": "user"})
        self.assertEqual(r.status_code, 200)
        senha = r.get_json()["password"]
        self.assertGreaterEqual(len(senha), 16)
        self.assertTrue(self.U.must_change_password("carla"))
        # A senha devolvida é a que realmente entra: precisa autenticar.
        self.U.change_own_password("carla", senha, "senha-da-carla-1")

    def test_senha_escolhida_pelo_admin_e_ignorada(self):
        r = self.app.post("/api/users", headers=self.ADMIN,
                          json={"name": "davi", "role": "user", "password": "123456789"})
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.get_json()["password"], "123456789")
        with self.assertRaises(self.U.UserError):
            self.U.change_own_password("davi", "123456789", "outra-senha-1")

    def test_senha_gerada_nunca_vai_para_a_auditoria(self):
        falso = _AuditFalso()
        anterior = self.webapp._audit_log
        self.webapp._audit_log = falso
        try:
            r = self.app.post("/api/users", headers=self.ADMIN,
                              json={"name": "erica", "role": "user"})
        finally:
            self.webapp._audit_log = anterior
        senha = r.get_json()["password"]
        self.assertTrue(falso.linhas, "a criação de conta precisa ser auditada")
        for linha in falso.linhas:
            self.assertNotIn(senha, linha)


if __name__ == "__main__":
    unittest.main()
