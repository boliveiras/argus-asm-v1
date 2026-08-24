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


# ── Interface (páginas estáticas) ────────────────────────────────────────────

class TestPagina(unittest.TestCase):
    """O portal é HTML estático: quem leva o usuário à troca é o JS que consulta
    /api/me. Sem isso ele veria telas cujos dados nunca carregam."""

    @classmethod
    def setUpClass(cls):
        import reporter
        cls.R = reporter
        cls.html = reporter.build_users_page()

    def test_boot_desvia_para_a_troca_de_senha(self):
        self.assertIn("must_change_password", self.R._RBAC_BOOT_JS)
        self.assertIn("/usuarios.html", self.R._RBAC_BOOT_JS)

    def test_pagina_tem_o_estado_de_senha_inicial(self):
        self.assertIn("u-trocar", self.html)
        self.assertIn("Troque a senha para continuar", self.html)

    def test_pagina_mostra_a_senha_gerada_uma_vez(self):
        self.assertIn("u-senha-box", self.html)
        self.assertIn("não é guardada", self.html)

    def test_admin_nao_escolhe_mais_a_senha_inicial(self):
        # O campo de senha no formulário de criação sumiu: quem gera é o servidor.
        self.assertNotIn('id="u-new-pw"', self.html)
        self.assertIn("JSON.stringify({name:name,role:role})", self.R._USERS_SCRIPT)

    def test_bloco_da_propria_senha_aparece_uma_unica_vez(self):
        # Id repetido faria o getElementById devolver o formulário escondido.
        self.assertEqual(self.html.count('id="u-cur-pw"'), 1)
        self.assertEqual(self.html.count('id="u-self"'), 1)

    def test_admin_nao_escolhe_a_senha_ao_redefinir(self):
        # Redefinir segue o mesmo modelo da criação: o servidor gera, a tela mostra
        # uma vez. Um window.prompt aqui devolveria o "admin inventa senha".
        self.assertNotIn("window.prompt", self.R._USERS_SCRIPT)
        self.assertIn("reset_password", self.R._USERS_SCRIPT)


# ── Hash legado do Apache (md5-apr1) ─────────────────────────────────────────
# Vetores GERADOS pelo Apache/OpenSSL (`openssl passwd -apr1 -salt <s> <senha>`,
# byte a byte igual ao que o `htpasswd -m` grava). São eles que provam que a
# verificação do formato antigo confere com o mundo real — e não com ela mesma.
APR1 = {
    "senha-inicial-1":                        "$apr1$Xy9pQ2Lm$EhMnc886Vi1LP80EV8.Ma0",
    "senha-do-bob-1":                         "$apr1$aB3dE5fG$jFsdxtBcBiIIk3nq7LZtY1",
    "a":                                      "$apr1$12345678$68ZQVfPkWX/wcXr/41VxQ.",
    "senha-com-16-cha":                       "$apr1$zZzZzZzZ$kvrQ0fpADjRAoVce0n6HR/",
    "curto":                                  "$apr1$Q1$cX2cDLzyqLlaYJPK5eJJr0",
    "uma-senha-bem-longa-de-mais-de-32-bytes": "$apr1$LoNgSalt$e8nTpd0RCzZCgf/65rP4N.",
    # Acentuada em UTF-8 (os bytes que o navegador manda) — prova que a senha vai
    # para o hash como bytes, não como texto do locale.
    "sénhã-com-acentuação":                   "$apr1$uTf8SaLt$51TfXXVLfcc0fCMRqZTEw1",
    "ExatosDezesseis1":                       "$apr1$Ab$oZQR30ncaVDtiXgIwLnIW0",
}


class TestApr1(Base):
    def test_confere_com_os_vetores_do_apache(self):
        for senha, esperado in APR1.items():
            self.assertTrue(self.U._verify(senha, esperado), f"não validou {senha!r}")

    def test_senha_errada_nao_passa(self):
        for _, hashed in APR1.items():
            self.assertFalse(self.U._verify("nao-e-essa-senha", hashed))

    def test_hash_truncado_ou_estranho_nao_derruba(self):
        for ruim in ("$apr1$", "$apr1$sal", "$apr1$sal$", "$5$sha$xxx", "texto-solto", ""):
            self.assertFalse(self.U._verify("qualquer", ruim))


class TestMigracaoApr1(Base):
    """O cenário da VM: a conta nasceu com apr1 e está marcada. Ela precisa
    conseguir trocar a própria senha — senão o portal fica inacessível."""

    def _conta_apr1(self, nome="monitor", senha="senha-inicial-1"):
        self.htpasswd.write_text(f"{nome}:{APR1[senha]}\n", encoding="utf-8")
        self.U.mark_must_change(nome)

    def test_troca_de_senha_funciona_com_hash_apr1(self):
        self._conta_apr1()
        self.U.change_own_password("monitor", "senha-inicial-1", "senha-nova-99")
        self.assertFalse(self.U.must_change_password("monitor"))

    def test_a_senha_nova_e_gravada_em_bcrypt(self):
        self._conta_apr1()
        self.U.change_own_password("monitor", "senha-inicial-1", "senha-nova-99")
        novo = self.U._read_htpasswd()["monitor"]
        self.assertTrue(novo.startswith(("$2a$", "$2b$", "$2y$")), novo[:6])
        self.assertTrue(self.U._verify("senha-nova-99", novo))

    def test_senha_atual_errada_continua_recusada(self):
        self._conta_apr1()
        with self.assertRaises(self.U.UserError) as ctx:
            self.U.change_own_password("monitor", "chute", "senha-nova-99")
        self.assertIn("incorreta", str(ctx.exception))
        self.assertTrue(self.U.must_change_password("monitor"))

    def test_pela_api_o_usuario_marcado_se_destrava_sozinho(self):
        self._conta_apr1()
        import webapp
        app = webapp.create_app().test_client()
        h = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}
        self.assertEqual(app.get("/api/findings", headers=h).status_code, 403)
        r = app.post("/api/me/password", headers=h,
                     json={"current": "senha-inicial-1", "new": "senha-nova-99"})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertNotEqual(app.get("/api/findings", headers=h).status_code, 403)


# ── Group file do Apache (contenção dos relatórios estáticos) ────────────────

class TestGroupFile(Base):
    def _grupo(self) -> list[str]:
        texto = self.U.groups_path().read_text(encoding="utf-8").strip()
        nome, _, membros = texto.partition(":")
        self.assertEqual(nome, self.U.GROUP_NAME)
        return membros.split()

    def test_conta_marcada_fica_de_fora(self):
        self.U.create_user("ana", "senha-inicial-1", "user", must_change=True)
        self.U.create_user("bob", "senha-do-bob-1", "user")
        self.assertEqual(self._grupo(), ["bob"])

    def test_trocar_a_senha_poe_a_conta_no_grupo(self):
        self.U.create_user("ana", "senha-inicial-1", "user", must_change=True)
        self.U.change_own_password("ana", "senha-inicial-1", "senha-nova-99")
        self.assertIn("ana", self._grupo())

    def test_marcar_tira_do_grupo(self):
        self.U.create_user("ana", "senha-inicial-1", "user")
        self.assertIn("ana", self._grupo())
        self.U.mark_must_change("ana")
        self.assertNotIn("ana", self._grupo())

    def test_remover_usuario_tira_do_grupo(self):
        self.U.create_user("ana", "senha-inicial-1", "user")
        self.U.delete_user("ana")
        self.assertNotIn("ana", self._grupo())

    def test_admin_da_instalacao_entra_quando_nao_esta_marcado(self):
        self.htpasswd.write_text(f"monitor:{APR1['senha-inicial-1']}\n", encoding="utf-8")
        self.U.sync_group_file()
        self.assertEqual(self._grupo(), ["monitor"])
        self.U.mark_must_change("monitor")
        self.assertEqual(self._grupo(), [])

    def test_arquivo_e_legivel_pelo_apache(self):
        # O Apache roda como www-data e não está no grupo do serviço: se o arquivo
        # não for legível por "outros", TODO relatório é negado a TODO mundo.
        self.U.create_user("ana", "senha-inicial-1", "user")
        modo = self.U.groups_path().stat().st_mode & 0o777
        self.assertTrue(modo & 0o004, oct(modo))

    def test_uma_linha_so_no_formato_do_apache(self):
        self.U.create_user("ana", "senha-inicial-1", "user")
        texto = self.U.groups_path().read_text(encoding="utf-8")
        self.assertEqual(texto.count("\n"), 1)
        self.assertTrue(texto.startswith(f"{self.U.GROUP_NAME}:"))


class TestApacheConfDoGrupo(unittest.TestCase):
    """A contenção só existe se o Apache a aplicar: o JS do portal não segura
    quem baixa o HTML com curl."""

    @classmethod
    def setUpClass(cls):
        cls.conf = Path("install.sh").read_text(encoding="utf-8", errors="replace")

    def test_docroot_exige_o_grupo(self):
        self.assertIn("AuthGroupFile", self.conf)
        self.assertIn("Require group liberados", self.conf)

    def test_a_tela_de_troca_e_o_login_continuam_alcancaveis(self):
        # Fechar usuarios.html/index.html junto trancaria a própria saída.
        self.assertIn('<Files "usuarios.html">', self.conf)
        self.assertIn('<Files "index.html">', self.conf)
        self.assertIn('<Files "login.html">', self.conf)

    def test_todos_os_relatorios_ficam_atras_do_grupo(self):
        # Nenhum <Files> pode devolver um relatório com dado embutido ao valid-user.
        for rel in ("findings_report.html", "monitor_report.html", "submonitor_report.html",
                    "credentials_report.html", "email_report.html", "typosquat_report.html"):
            self.assertNotIn(f'<Files "{rel}">', self.conf)


# ── users.json ilegível: anomalia NEGA, ausência libera ──────────────────────

class TestRolesIndisponivel(BaseWeb):
    def _corromper(self):
        self.U.roles_path().write_text("{ isto não é json", encoding="utf-8")

    def test_arquivo_ausente_e_legitimo(self):
        self.U.roles_path().unlink()
        self.assertEqual(self.U._read_roles(), {})
        self.assertFalse(self.U.must_change_password("ana"))

    def test_json_invalido_e_anomalia(self):
        self._corromper()
        with self.assertRaises(self.U.RolesUnavailable):
            self.U._read_roles()

    def test_json_que_nao_e_objeto_e_anomalia(self):
        self.U.roles_path().write_text("[1,2,3]", encoding="utf-8")
        with self.assertRaises(self.U.RolesUnavailable):
            self.U._read_roles()

    def test_guard_nega_quando_o_arquivo_esta_corrompido(self):
        # Sem isto, `monitor` viraria admin PLENO sem marca — o papel vem do nome.
        self._corromper()
        r = self.app.get("/api/findings",
                         headers={"X-Requested-With": "argus", "X-Remote-User": "monitor"})
        self.assertEqual(r.status_code, 403)

    def test_anomalia_vai_para_a_auditoria(self):
        self._corromper()
        falso = _AuditFalso()
        anterior = self.webapp._audit_log
        self.webapp._audit_log = falso
        try:
            self.app.get("/api/findings", headers=self.LIVRE)
        finally:
            self.webapp._audit_log = anterior
        self.assertTrue(any("AUTHZ_DENY" in linha for linha in falso.linhas), falso.linhas)


# ── Erro DEPOIS da senha já trocada ──────────────────────────────────────────

class TestTrocaParcial(BaseWeb):
    def _quebrar_write_roles(self):
        """Simula o disco cheio DEPOIS que o hash novo já entrou no htpasswd."""
        def explode(_roles):
            raise OSError("disco cheio")
        self.addCleanup(setattr, self.U, "_write_roles", self.U._write_roles)
        self.U._write_roles = explode

    def test_mensagem_diz_que_a_senha_ja_mudou(self):
        self._quebrar_write_roles()
        with self.assertRaises(self.U.PasswordChangedIncomplete) as ctx:
            self.U.change_own_password("ana", "senha-inicial-1", "senha-nova-99")
        texto = str(ctx.exception).lower()
        self.assertIn("nova senha", texto)
        # A senha NOVA é a que vale a partir de agora — a mensagem precisa dizer isso.
        self.assertTrue(self.U._verify("senha-nova-99", self.U._read_htpasswd()["ana"]))

    def test_api_responde_sinalizando_que_a_senha_mudou(self):
        self._quebrar_write_roles()
        r = self.app.post("/api/me/password", headers=self.MARCADO,
                          json={"current": "senha-inicial-1", "new": "senha-nova-99"})
        self.assertEqual(r.status_code, 500)
        self.assertTrue(r.get_json()["password_changed"])


# ── Redefinição pelo administrador ───────────────────────────────────────────

class TestRedefinicaoPeloAdmin(BaseWeb):
    def setUp(self):
        super().setUp()
        self.ADMIN = {"X-Requested-With": "argus", "X-Remote-User": "monitor"}

    def test_set_password_gera_a_senha_e_marca_a_conta(self):
        res = self.U.set_password("bob")
        self.assertGreaterEqual(len(res["password"]), 16)
        self.assertTrue(self.U.must_change_password("bob"))
        self.U.change_own_password("bob", res["password"], "senha-do-bob-2")

    def test_senha_enviada_pelo_admin_e_ignorada(self):
        r = self.app.post("/api/users/bob", headers=self.ADMIN,
                          json={"reset_password": True, "password": "123456789"})
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.get_json()["password"], "123456789")
        self.assertTrue(self.U.must_change_password("bob"))

    def test_a_conta_redefinida_sai_do_grupo_liberado(self):
        self.app.post("/api/users/bob", headers=self.ADMIN, json={"reset_password": True})
        membros = self.U.groups_path().read_text(encoding="utf-8").partition(":")[2].split()
        self.assertNotIn("bob", membros)

    def test_a_senha_redefinida_nunca_vai_para_a_auditoria(self):
        falso = _AuditFalso()
        anterior = self.webapp._audit_log
        self.webapp._audit_log = falso
        try:
            r = self.app.post("/api/users/bob", headers=self.ADMIN, json={"reset_password": True})
        finally:
            self.webapp._audit_log = anterior
        senha = r.get_json()["password"]
        self.assertTrue(falso.linhas)
        for linha in falso.linhas:
            self.assertNotIn(senha, linha)


# ── Permissões de users.json ─────────────────────────────────────────────────

class TestPermissoesDoUsersJson(Base):
    @unittest.skipUnless(hasattr(os, "chown"), "dono/modo de arquivo é conceito POSIX")
    def test_reescrever_preserva_o_modo(self):
        self.U.mark_must_change("monitor")
        p = self.U.roles_path()
        # 0660 é exatamente o modo que o instalador aplica (root:argus): o teste
        # existe para provar que uma reescrita NÃO o troca pelo umask.
        os.chmod(p, 0o660)  # nosec B103 - modo sob teste, em arquivo temporário
        self.U.mark_must_change("outro")
        self.assertEqual(p.stat().st_mode & 0o777, 0o660)


# ── Recuperação por console (SSH) ────────────────────────────────────────────

class TestCliDeRecuperacao(Base):
    def _cli(self, *args):
        import subprocess
        env = dict(os.environ)
        env["PYTHONPATH"] = "core"
        return subprocess.run([sys.executable, "core/users.py", *args],
                              capture_output=True, text=True, env=env, check=False)

    def test_limpar_marca_destrava_a_conta(self):
        self.U.create_user("ana", "senha-inicial-1", "user", must_change=True)
        res = self._cli("--limpar-marca", "ana")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(self.U.must_change_password("ana"))

    def test_limpar_marca_de_quem_nao_existe_falha(self):
        self.assertNotEqual(self._cli("--limpar-marca", "ninguem").returncode, 0)

    def test_sincronizar_grupos_recria_o_arquivo(self):
        self.U.create_user("ana", "senha-inicial-1", "user")
        self.U.groups_path().unlink()
        self.assertEqual(self._cli("--sincronizar-grupos").returncode, 0)
        self.assertIn("ana", self.U.groups_path().read_text(encoding="utf-8"))

    def test_uso_invalido_sai_com_erro(self):
        self.assertEqual(self._cli("--coisa-que-nao-existe").returncode, 2)


class TestDocumentacaoDaRecuperacao(unittest.TestCase):
    def test_readme_diz_como_destravar(self):
        readme = Path("README.md").read_text(encoding="utf-8", errors="replace")
        self.assertIn("--limpar-marca", readme)

    def test_docs_do_portal_descrevem_a_contencao_real(self):
        # A promessa antiga ("não dá acesso a achado algum") só passou a ser
        # verdade com o group file no Apache. O texto tem de dizer o que a versão
        # entrega — nem mais, nem menos.
        import docs
        secao = "".join("".join(s) for s in docs.SECOES if s[0] == "usuarios")
        self.assertTrue(secao, "seção 'usuarios' sumiu da ajuda")
        self.assertNotIn("não dá acesso a achado", secao)
        # O que segura os relatórios é o Apache (group file), não o JS do portal.
        self.assertIn("relatório", secao.lower())


if __name__ == "__main__":
    unittest.main()
