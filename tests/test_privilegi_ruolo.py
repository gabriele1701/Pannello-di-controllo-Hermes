"""Il ruolo applicativo non puo' aggirare i propri vincoli.

Questo file e' la dimostrazione del motivo per cui esistono due ruoli di
database, e chiude un buco che la prima versione del progetto aveva lasciato
aperto.

Il buco
-------

La migrazione 0001 ha messo gli invarianti del dominio in trigger di
PostgreSQL, e il README affermava che quei vincoli non si aggirano. Vero per
chi passa dalle tabelle, falso per chi le possiede: **il proprietario di una
tabella puo' disabilitarne i trigger.**

    ALTER TABLE tier_overrides DISABLE TRIGGER ALL;
    -- da qui un override a `verde` passa

Finche' l'applicazione si connetteva con il ruolo proprietario, quel comando
era a disposizione del codice applicativo, e quindi di qualunque suo difetto.
«Il vincolo e' nel database, non nell'applicazione» descriveva *dove stava
scritto* il vincolo, non *chi poteva toglierlo*.

Cosa prova questo file
----------------------

Che il ruolo con cui l'applicazione gira in esercizio non arriva al
comando. I test sono divisi in tre gruppi, che sono tre modi diversi di
provare a vincere:

1. **disattivare** il meccanismo (`DISABLE TRIGGER`,
   `session_replication_role`);
2. **rimuoverlo** (`DROP TRIGGER`, `DROP FUNCTION`, `DROP CONSTRAINT`,
   `DROP TABLE`);
3. **passargli accanto**, scrivendo dove non si deve (`UPDATE`/`DELETE` su
   una tabella append-only, `INSERT` nel log, `TRUNCATE`).

I primi due gruppo sono bloccati dalla **proprieta'**: il ruolo non possiede
niente. Il terzo dai **privilegi**: le concessioni sono scritte per tabella,
e per tre tabelle su sette la concessione di scrittura non c'e' affatto.

Si noti che il terzo gruppo era gia' coperto dai trigger. Ora e' coperto due
volte, da due meccanismi indipendenti: il privilegio manca, e se anche ci
fosse il trigger rifiuterebbe. E' il verso giusto in cui essere ridondanti.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from tests.helpers import sqlstate

#: Tabelle che reggono gli invarianti append-only.
TABELLE_APPEND_ONLY = ("tier_overrides", "audit_events")


def _esegui_come_app(engine_app: Engine, sql: str, **parametri) -> None:
    """Esegue una istruzione con il ruolo applicativo, in una transazione sua."""
    with engine_app.begin() as conn:
        conn.execute(text(sql), parametri)


def _errore(engine_app: Engine, sql: str, **parametri) -> ProgrammingError:
    """Esegue e pretende un rifiuto, restituendolo."""
    with pytest.raises(ProgrammingError) as info:
        _esegui_come_app(engine_app, sql, **parametri)
    return info.value


def _messaggio(exc: BaseException) -> str:
    return str(exc).lower()


# --------------------------------------------------------------------------- #
# Prerequisito: il ruolo e' davvero quello che diciamo
# --------------------------------------------------------------------------- #


def test_il_ruolo_applicativo_non_e_superutente(engine_app: Engine) -> None:
    """Non superutente, non createdb, non createrole, non bypassrls.

    Se fosse superutente tutto il resto di questo file passerebbe per caso:
    un superutente puo' fare qualunque cosa, quindi i test non starebbero
    verificando niente.
    """
    with engine_app.connect() as conn:
        riga = conn.execute(
            text(
                """
                SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
                FROM pg_roles WHERE rolname = current_user
                """
            )
        ).one()
    assert riga.rolsuper is False, "il ruolo applicativo non deve essere superutente"
    assert riga.rolcreatedb is False
    assert riga.rolcreaterole is False
    assert riga.rolbypassrls is False


def test_il_ruolo_applicativo_non_possiede_le_tabelle(engine_app: Engine) -> None:
    """La proprieta' e' cio' che blocca DISABLE TRIGGER e DROP."""
    with engine_app.connect() as conn:
        proprietari = dict(
            conn.execute(
                text(
                    """
                    SELECT tablename, tableowner FROM pg_tables
                    WHERE schemaname = 'public'
                    """
                )
            ).all()
        )
        utente = conn.execute(text("SELECT current_user")).scalar_one()

    assert proprietari, "nessuna tabella trovata: lo schema non e' stato creato"
    for tabella, proprietario in proprietari.items():
        assert proprietario != utente, (
            f"{tabella} e' posseduta dal ruolo applicativo: potrebbe "
            f"disabilitarne i trigger"
        )


def test_i_due_ruoli_sono_diversi(engine: Engine, engine_app: Engine) -> None:
    """Se fossero lo stesso ruolo, la separazione sarebbe solo nei commenti."""
    with engine.connect() as conn:
        proprietario = conn.execute(text("SELECT current_user")).scalar_one()
    with engine_app.connect() as conn:
        applicativo = conn.execute(text("SELECT current_user")).scalar_one()
    assert proprietario != applicativo
    assert applicativo == "hermes_app"


# --------------------------------------------------------------------------- #
# Gruppo 1 — disattivare il meccanismo
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tabella", TABELLE_APPEND_ONLY)
def test_non_puo_disabilitare_i_trigger(engine_app: Engine, tabella: str) -> None:
    """**Il test che e' la dimostrazione.**

    `ALTER TABLE ... DISABLE TRIGGER ALL` e' il comando che renderebbe
    inoffensivi tutti i trigger della migrazione 0001 in una riga sola. Il
    ruolo applicativo non e' proprietario, quindi PostgreSQL lo rifiuta
    prima di guardare qualunque altra cosa.
    """
    exc = _errore(engine_app, f"ALTER TABLE {tabella} DISABLE TRIGGER ALL")
    assert "must be owner" in _messaggio(exc), _messaggio(exc)


def test_non_puo_disabilitare_un_singolo_trigger(engine_app: Engine) -> None:
    exc = _errore(
        engine_app,
        "ALTER TABLE tier_overrides DISABLE TRIGGER tier_overrides_monotonia_trg",
    )
    assert "must be owner" in _messaggio(exc)


def test_non_puo_cambiare_session_replication_role(engine_app: Engine) -> None:
    """La seconda via per spegnere i trigger, e la piu' corta.

    `SET session_replication_role = replica` impedisce ai trigger utente di
    scattare per tutta la sessione, senza toccare nessuna tabella. Richiede
    il superutente, e il ruolo applicativo non lo e'.
    """
    exc = _errore(engine_app, "SET session_replication_role = 'replica'")
    testo = _messaggio(exc)
    assert "permission denied to set parameter" in testo
    assert "session_replication_role" in testo


def test_i_trigger_sono_attivi(engine: Engine) -> None:
    """Controprova: i trigger che i test sopra non riescono a spegnere ci sono.

    Senza questa verifica, i test precedenti passerebbero anche su uno schema
    privo di trigger -- `DISABLE TRIGGER` fallirebbe comunque per mancanza di
    proprieta', e non si saprebbe di non avere niente da disabilitare.
    """
    with engine.connect() as conn:
        trigger = {
            riga[0]
            for riga in conn.execute(
                text(
                    """
                    SELECT tgname FROM pg_trigger t
                    JOIN pg_class c ON c.oid = t.tgrelid
                    WHERE NOT t.tgisinternal
                      AND c.relname IN ('tier_overrides', 'audit_events',
                                        'scope_aliases', 'scope_networks')
                      AND t.tgenabled = 'O'
                    """
                )
            ).all()
        }
    attesi = {
        "tier_overrides_monotonia_trg",
        "tier_overrides_append_only_trg",
        "tier_overrides_no_truncate_trg",
        "audit_events_append_only_trg",
        "audit_events_no_truncate_trg",
        "scope_aliases_dentro_perimetro_trg",
        "scope_networks_no_alias_orfani_trg",
    }
    assert attesi <= trigger, f"trigger mancanti o disattivati: {attesi - trigger}"


# --------------------------------------------------------------------------- #
# Gruppo 2 — rimuovere il meccanismo invece di disattivarlo
# --------------------------------------------------------------------------- #


def test_non_puo_rimuovere_il_trigger_di_monotonia(engine_app: Engine) -> None:
    exc = _errore(
        engine_app,
        "DROP TRIGGER tier_overrides_monotonia_trg ON tier_overrides",
    )
    assert "must be owner" in _messaggio(exc)


def test_non_puo_rimuovere_la_funzione_del_trigger(engine_app: Engine) -> None:
    exc = _errore(engine_app, "DROP FUNCTION tier_overrides_monotonia()")
    assert "must be owner" in _messaggio(exc)


def test_non_puo_sostituire_la_funzione_del_trigger(engine_app: Engine) -> None:
    """`CREATE OR REPLACE` sarebbe il modo elegante di svuotare il vincolo.

    Una funzione che restituisce NEW senza controllare niente lascerebbe il
    trigger in piedi, attivo e inoffensivo -- e un'ispezione di `pg_trigger`
    non mostrerebbe nulla di strano.
    """
    exc = _errore(
        engine_app,
        """
        CREATE OR REPLACE FUNCTION tier_overrides_monotonia() RETURNS trigger
        LANGUAGE plpgsql AS $fn$ BEGIN RETURN NEW; END; $fn$
        """,
    )
    testo = _messaggio(exc)
    assert "must be owner" in testo or "permission denied" in testo, testo


def test_non_puo_rimuovere_un_vincolo(engine_app: Engine) -> None:
    exc = _errore(
        engine_app,
        "ALTER TABLE tier_overrides DROP CONSTRAINT tier_overrides_reason_non_vuoto",
    )
    assert "must be owner" in _messaggio(exc)


@pytest.mark.parametrize("tabella", TABELLE_APPEND_ONLY)
def test_non_puo_rimuovere_la_tabella(engine_app: Engine, tabella: str) -> None:
    exc = _errore(engine_app, f"DROP TABLE {tabella}")
    assert "must be owner" in _messaggio(exc)


def test_non_puo_creare_oggetti_nello_schema(engine_app: Engine) -> None:
    """Senza CREATE sullo schema il ruolo non si costruisce scappatoie."""
    exc = _errore(engine_app, "CREATE TABLE scappatoia (x int)")
    assert "permission denied for schema public" in _messaggio(exc)


def test_non_vede_la_versione_dello_schema(engine_app: Engine) -> None:
    """`alembic_version` non e' raggiungibile.

    L'applicazione non deve poter leggere ne' alterare quale versione dello
    schema e' applicata: non le serve, e poterla scrivere significherebbe
    poter mentire a una migrazione futura su cosa e' gia' stato applicato.
    """
    exc = _errore(engine_app, "SELECT * FROM alembic_version")
    assert "permission denied" in _messaggio(exc)


# --------------------------------------------------------------------------- #
# Gruppo 3 — scrivere dove non si deve
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tabella", TABELLE_APPEND_ONLY)
@pytest.mark.parametrize("operazione", ["UPDATE {t} SET id = id", "DELETE FROM {t}", "TRUNCATE {t}"])
def test_nessuna_modifica_sulle_tabelle_append_only(
    engine_app: Engine, tabella: str, operazione: str
) -> None:
    """Append-only applicato due volte: dai privilegi e dai trigger.

    Qui il rifiuto arriva dal **privilegio** -- il ruolo non ha UPDATE,
    DELETE ne' TRUNCATE su queste tabelle -- quindi la richiesta non raggiunge
    nemmeno il trigger. Che il trigger funzioni comunque e' provato in
    `test_db_constraints.py`, che gira con il ruolo proprietario.
    """
    exc = _errore(engine_app, operazione.format(t=tabella))
    assert f"permission denied for table {tabella}" in _messaggio(exc)


def test_non_puo_scrivere_nel_log(engine_app: Engine) -> None:
    """«Nessuna rotta scrive nel log» diventa «nessuna scrittura e' possibile».

    E' un'affermazione diversa e piu' forte: la prima dipende dal fatto che
    nessuno aggiunga una rotta, la seconda no.
    """
    exc = _errore(
        engine_app,
        """
        INSERT INTO audit_events (correlation_id, event_type, outcome, detail)
        VALUES (gen_random_uuid(), 'tool_call', 'ok', 'riga inserita a mano')
        """,
    )
    assert "permission denied for table audit_events" in _messaggio(exc)


@pytest.mark.parametrize(
    "sql",
    [
        """INSERT INTO tools (tool_id, agent, declared_tier, personal_data,
                              exec_path, exec_sha256, description)
           VALUES ('x.y', 'pentest_kali', 'verde', false, 'a.py',
                   '0000000000000000000000000000000000000000000000000000000000000000',
                   'x')""",
        "UPDATE tools SET declared_tier = 'verde'",
        "UPDATE tools SET exec_sha256 = '" + "0" * 64 + "'",
        "DELETE FROM tools",
    ],
)
def test_tools_e_in_sola_lettura(engine_app: Engine, sql: str) -> None:
    """Lo SPEC dice che l'identita' di un tool e' di sola lettura qui.

    `(exec_path, exec_sha256, exec_args)` e' cio' che viene davvero eseguito,
    e lo registra hermes-core. Prima lo garantiva l'assenza di una rotta; ora
    lo garantisce l'assenza del privilegio, che e' una garanzia che non
    dipende da chi scrivera' la prossima rotta.
    """
    exc = _errore(engine_app, sql)
    assert "permission denied for table tools" in _messaggio(exc)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE users SET password_hash = '$argon2id$finto'",
        "INSERT INTO users (username, password_hash) VALUES ('altro', '$argon2id$x')",
        "DELETE FROM users",
    ],
)
def test_users_e_in_sola_lettura(engine_app: Engine, sql: str) -> None:
    """L'applicazione autentica, non amministra gli account.

    Non c'e' una rotta per cambiare la password, quindi non c'e' il
    privilegio. Se la rotta arrivera', servira' una migrazione che concede
    l'UPDATE -- cioe' una decisione esplicita, in un file che si rilegge in
    review.
    """
    exc = _errore(engine_app, sql)
    assert "permission denied for table users" in _messaggio(exc)


@pytest.mark.parametrize(
    "colonna",
    ["expires_at = now() + interval '10 years'", "scope = 'tutto'", "agent = 'orchestrator'"],
)
def test_di_un_consenso_puo_scrivere_solo_la_revoca(
    engine_app: Engine, colonna: str
) -> None:
    """Concessione a livello di colonna: un consenso si revoca, non si riscrive.

    L'applicazione puo' scrivere `revoked_at` e nient'altro. Non puo'
    prolungare la scadenza di un consenso gia' dato, ne' cambiarne l'agente o
    lo scope: sarebbero un consenso diverso da quello che l'operatore ha
    firmato, con lo stesso identificativo.
    """
    exc = _errore(engine_app, f"UPDATE scope_consents SET {colonna}")
    # PostgreSQL riporta «permission denied for table» e non «for column»:
    # il ruolo non ha UPDATE a livello di tabella, e la concessione che ha su
    # `revoked_at` non copre la colonna che la query tocca. Il rifiuto e'
    # quello giusto, il nome nel messaggio e' il nome della tabella.
    testo = _messaggio(exc)
    assert "permission denied" in testo
    assert "scope_consents" in testo


def test_la_revoca_e_lunica_colonna_scrivibile(
    engine_app: Engine, dati_esempio: Session
) -> None:
    """Controprova del test sopra.

    Senza questa, `test_di_un_consenso_puo_scrivere_solo_la_revoca` passerebbe
    anche se il ruolo non avesse NESSUNA concessione di scrittura su
    `scope_consents`: il rifiuto ci sarebbe comunque, e non si saprebbe di
    aver tolto anche la revoca.
    """
    with engine_app.begin() as conn:
        consenso = conn.execute(
            text(
                """
                INSERT INTO scope_consents (agent, scope, granted_by, expires_at)
                VALUES ('vuln_assessment', 'lab-web', 'test',
                        now() + interval '2 days')
                RETURNING id
                """
            )
        ).scalar_one()

    with engine_app.begin() as conn:
        conn.execute(
            text("UPDATE scope_consents SET revoked_at = now() WHERE id = :i"),
            {"i": consenso},
        )

    with engine_app.connect() as conn:
        assert (
            conn.execute(
                text("SELECT revoked_at FROM scope_consents WHERE id = :i"),
                {"i": consenso},
            ).scalar_one()
            is not None
        )


# --------------------------------------------------------------------------- #
# Controprova: le concessioni bastano per il lavoro vero
# --------------------------------------------------------------------------- #


def test_lurl_del_ruolo_applicativo_porta_la_password_vera() -> None:
    """Guardia contro una regressione che la CI ha trovato e il locale no.

    L'URL del ruolo applicativo si deriva da quella privilegiata cambiando
    utente e password. Scriverlo con `str(url)` sembra funzionare e non
    funziona: SQLAlchemy sostituisce la password con `***` in `__str__`, come
    protezione contro le password nei log. Il risultato e' un URL la cui
    password e' letteralmente `***`.

    Su un cluster di sviluppo con autenticazione `trust` quell'URL si collega
    comunque -- qualunque password e' accettata -- quindi l'errore e'
    invisibile in locale e appare solo dove l'autenticazione e' reale.

    Questo test lo rende visibile sempre: non apre nessuna connessione,
    guarda la stringa.
    """
    from tests.conftest import PASSWORD_RUOLO_APP, _url_applicativa

    url = _url_applicativa()
    assert "***" not in url, (
        "la password e' stata mascherata: usare "
        "render_as_string(hide_password=False) invece di str()"
    )
    assert PASSWORD_RUOLO_APP in url
    assert "hermes_app" in url


def test_lapplicazione_si_connette_come_ruolo_applicativo(client) -> None:
    """La sessione che usano le rotte e' quella del ruolo con pochi privilegi.

    E' il presupposto di tutto questo file e di meta' del valore della suite:
    se l'applicazione sotto test si connettesse come proprietario, i test
    delle API passerebbero anche con concessioni sbagliate, e i test dei
    privilegi qui sopra verificherebbero un ruolo che in esercizio non viene
    usato da nessuno.

    `client` e' richiesto perche' costruisce l'applicazione: a quel punto la
    configurazione e' stata letta e il motore e' quello definitivo.
    """
    from backend.db import session_factory

    db = session_factory()()
    try:
        assert db.execute(text("SELECT current_user")).scalar_one() == "hermes_app"
        # E non e' proprietario di cio' che legge.
        proprietario = db.execute(
            text("SELECT tableowner FROM pg_tables WHERE tablename = 'tier_overrides'")
        ).scalar_one()
        assert proprietario != "hermes_app"
    finally:
        db.close()


def test_il_ruolo_applicativo_puo_fare_il_proprio_lavoro(
    engine: Engine, engine_app: Engine, dati_esempio: Session, nuovo_tool
) -> None:
    """Le concessioni sono minime, non insufficienti.

    Un insieme di privilegi che blocca tutto supererebbe ogni test di questo
    file e renderebbe l'applicazione inutilizzabile. Qui si verifica che il
    ruolo arrivi a fare le cose che deve: leggere il catalogo e la vista,
    innalzare un tier, modificare il perimetro, revocare un consenso.

    La prova piu' larga e' comunque un'altra: **l'intera suite delle API gira
    con questo ruolo**, perche' la fixture `engine` imposta `DATABASE_URL` su
    `hermes_app`. Se mancasse un GRANT, i test delle API lo troverebbero.
    """
    with engine_app.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM tools")).scalar_one() > 0
        assert (
            conn.execute(text("SELECT count(*) FROM tool_effective_tier")).scalar_one()
            > 0
        )
        assert conn.execute(text("SELECT count(*) FROM audit_events")).scalar_one() > 0

    # Innalzamento: INSERT su tier_overrides, piu' il SELECT su tools e
    # l'advisory lock che il trigger esegue con i privilegi del chiamante.
    #
    # Su un tool creato per questo test, non su uno dei dati di esempio:
    # `tier_overrides` e' append-only, quindi un tool condiviso porterebbe
    # gli innalzamenti di un altro test dentro questo, e l'esito dipenderebbe
    # dall'ordine di esecuzione.
    tool_pk = nuovo_tool(declared_tier="verde")
    with engine_app.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO tier_overrides (tool_id, tier, reason, created_by)
                VALUES (:pk, 'rosso', 'prova delle concessioni minime', 'test')
                """
            ),
            {"pk": tool_pk},
        )

    with engine_app.connect() as conn:
        assert (
            conn.execute(
                text("SELECT effective_tier FROM tool_effective_tier WHERE tool_pk = :pk"),
                {"pk": tool_pk},
            ).scalar_one()
            == "rosso"
        )

    # Perimetro: INSERT e DELETE.
    with engine_app.begin() as conn:
        conn.execute(
            text("INSERT INTO scope_networks (cidr, label) VALUES ('10.9.0.0/24', 'Prova')")
        )
        conn.execute(text("DELETE FROM scope_networks WHERE cidr = '10.9.0.0/24'"))

    # Consenso: INSERT, e UPDATE della sola colonna revoked_at.
    with engine_app.begin() as conn:
        consenso = conn.execute(
            text(
                """
                INSERT INTO scope_consents (agent, scope, granted_by, expires_at)
                VALUES ('pentest_kali', '192.168.205.0/24', 'test',
                        now() + interval '1 day')
                RETURNING id
                """
            )
        ).scalar_one()
        conn.execute(
            text("UPDATE scope_consents SET revoked_at = now() WHERE id = :i"),
            {"i": consenso},
        )


def test_il_trigger_di_monotonia_scatta_anche_per_il_ruolo_applicativo(
    engine_app: Engine, dati_esempio: Session
) -> None:
    """Il vincolo vale per chi gira in esercizio, non solo per il proprietario.

    E' la chiusura del cerchio: il ruolo applicativo non puo' spegnere il
    trigger (gruppo 1), non puo' rimuoverlo (gruppo 2), e quando scrive il
    trigger lo rifiuta (questo test). I tre gruppi insieme sono
    l'affermazione che il README fa.
    """
    with engine_app.connect() as conn:
        tool_pk = conn.execute(
            text("SELECT id FROM tools WHERE tool_id = 'recon.nmap-sweep'")
        ).scalar_one()

    # recon.nmap-sweep e' a `rosso` nei dati di esempio.
    with pytest.raises(Exception) as info:
        _esegui_come_app(
            engine_app,
            """
            INSERT INTO tier_overrides (tool_id, tier, reason, created_by)
            VALUES (:pk, 'giallo', 'provo ad abbassarlo', 'attaccante')
            """,
            pk=tool_pk,
        )
    assert sqlstate(info.value) == "HM409"
    assert "solo salire" in _messaggio(info.value)
