"""Gli invarianti del dominio, verificati in SQL diretto.

Questi test non passano dall'API. Interrogano il database come lo farebbe
qualcuno con una console `psql` aperta, e sono il motivo per cui i vincoli
stanno nel database: se vivessero nel codice Python, questa suite
passerebbe senza che niente protegga lo stato reale.

Il criterio di accettazione dice «rifiutato sia dall'API sia dal database se
la query viene eseguita a mano»: questo file e' la seconda meta'.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from tests.conftest import sqlstate

# --------------------------------------------------------------------------- #
# Monotonia del tier
# --------------------------------------------------------------------------- #


def _override(db: Session, tool_pk: int, tier: str, motivo: str = "motivo di prova"):
    return db.execute(
        text(
            """
            INSERT INTO tier_overrides (tool_id, tier, reason, created_by)
            VALUES (:tool, :tier, :motivo, 'test')
            RETURNING id
            """
        ),
        {"tool": tool_pk, "tier": tier, "motivo": motivo},
    ).scalar_one()


def _tier_effettivo(db: Session, tool_pk: int) -> str:
    return db.execute(
        text("SELECT effective_tier FROM tool_effective_tier WHERE tool_pk = :pk"),
        {"pk": tool_pk},
    ).scalar_one()


def test_innalzamento_verso_tier_superiore_accettato(db: Session, nuovo_tool) -> None:
    pk = nuovo_tool(declared_tier="verde")
    _override(db, pk, "giallo")
    db.commit()
    assert _tier_effettivo(db, pk) == "giallo"


def test_innalzamento_a_due_passi_accettato(db: Session, nuovo_tool) -> None:
    """verde -> giallo -> rosso: ogni passo sale, quindi ogni passo passa."""
    pk = nuovo_tool(declared_tier="verde")
    _override(db, pk, "giallo")
    _override(db, pk, "rosso")
    db.commit()
    assert _tier_effettivo(db, pk) == "rosso"


def test_salto_di_un_livello_accettato(db: Session, nuovo_tool) -> None:
    """verde -> rosso direttamente: non c'e' obbligo di passare dal giallo."""
    pk = nuovo_tool(declared_tier="verde")
    _override(db, pk, "rosso")
    db.commit()
    assert _tier_effettivo(db, pk) == "rosso"


@pytest.mark.parametrize(
    ("dichiarato", "tentato"),
    [
        ("giallo", "verde"),
        ("rosso", "verde"),
        ("rosso", "giallo"),
    ],
)
def test_declassamento_sotto_il_tier_dichiarato_rifiutato(
    db: Session, nuovo_tool, dichiarato: str, tentato: str
) -> None:
    """Il tier dichiarato e' un pavimento: nessun override scende sotto.

    E' l'invariante centrale. Un declassamento sarebbe un modo di
    disattivare i controlli di sicurezza senza toccarne il codice.
    """
    pk = nuovo_tool(declared_tier=dichiarato)
    with pytest.raises(DBAPIError) as errore:
        _override(db, pk, tentato)
    assert sqlstate(errore.value) == "HM409"
    db.rollback()
    assert _tier_effettivo(db, pk) == dichiarato


def test_declassamento_sotto_un_override_rifiutato(db: Session, nuovo_tool) -> None:
    """Anche un override gia' registrato diventa un pavimento."""
    pk = nuovo_tool(declared_tier="verde")
    _override(db, pk, "rosso")
    db.commit()
    with pytest.raises(DBAPIError) as errore:
        _override(db, pk, "giallo")
    assert sqlstate(errore.value) == "HM409"
    db.rollback()
    assert _tier_effettivo(db, pk) == "rosso"


def test_override_pari_al_tier_corrente_rifiutato(db: Session, nuovo_tool) -> None:
    """Un override che non innalza non e' un innalzamento.

    Accettarlo riempirebbe lo storico di righe inerti, e lo storico e' cio'
    che si legge per capire perche' un tool sta dov'e'.
    """
    pk = nuovo_tool(declared_tier="giallo")
    with pytest.raises(DBAPIError) as errore:
        _override(db, pk, "giallo")
    assert sqlstate(errore.value) == "HM409"
    db.rollback()


def test_override_su_tool_inesistente_rifiutato(db: Session) -> None:
    with pytest.raises(DBAPIError):
        _override(db, 10**9, "rosso")
    db.rollback()


def test_motivo_vuoto_rifiutato(db: Session, nuovo_tool) -> None:
    """NOT NULL non basta: la stringa vuota soddisfa NOT NULL e non dice niente."""
    pk = nuovo_tool(declared_tier="verde")
    with pytest.raises(IntegrityError):
        _override(db, pk, "giallo", motivo="   ")
    db.rollback()


def test_vista_riporta_il_pavimento_anche_senza_override(
    db: Session, nuovo_tool
) -> None:
    pk = nuovo_tool(declared_tier="giallo")
    riga = db.execute(
        text(
            """
            SELECT declared_tier, effective_tier, override_count
            FROM tool_effective_tier WHERE tool_pk = :pk
            """
        ),
        {"pk": pk},
    ).one()
    assert riga.declared_tier == "giallo"
    assert riga.effective_tier == "giallo"
    assert riga.override_count == 0


# --------------------------------------------------------------------------- #
# Append-only
# --------------------------------------------------------------------------- #


def test_update_su_tier_overrides_rifiutato(db: Session, nuovo_tool) -> None:
    pk = nuovo_tool(declared_tier="verde")
    override_id = _override(db, pk, "giallo")
    db.commit()
    with pytest.raises(DBAPIError) as errore:
        db.execute(
            text("UPDATE tier_overrides SET tier = 'rosso' WHERE id = :i"),
            {"i": override_id},
        )
    assert sqlstate(errore.value) == "HM403"
    db.rollback()


def test_delete_su_tier_overrides_rifiutato(db: Session, nuovo_tool) -> None:
    """Non esiste annullamento di un override: sarebbe un declassamento."""
    pk = nuovo_tool(declared_tier="verde")
    override_id = _override(db, pk, "giallo")
    db.commit()
    with pytest.raises(DBAPIError) as errore:
        db.execute(
            text("DELETE FROM tier_overrides WHERE id = :i"), {"i": override_id}
        )
    assert sqlstate(errore.value) == "HM403"
    db.rollback()


def test_truncate_su_tier_overrides_rifiutato(db: Session) -> None:
    """TRUNCATE non passa dai trigger di riga: serve un trigger di statement.

    Senza, «append-only» sarebbe vero solo per le operazioni che qualcuno si
    e' ricordato di coprire.
    """
    with pytest.raises(DBAPIError) as errore:
        db.execute(text("TRUNCATE tier_overrides"))
    assert sqlstate(errore.value) == "HM403"
    db.rollback()


def _evento(db: Session) -> int:
    return db.execute(
        text(
            """
            INSERT INTO audit_events (correlation_id, event_type, agent, tool_id,
                                      outcome, authorized_by, detail)
            VALUES (gen_random_uuid(), 'tool_call', 'vuln_assessment',
                    'prova.tool', 'ok', 'policy', 'riga di prova')
            RETURNING id
            """
        )
    ).scalar_one()


def test_update_su_audit_events_rifiutato(db: Session) -> None:
    evento_id = _evento(db)
    db.commit()
    with pytest.raises(DBAPIError) as errore:
        db.execute(
            text("UPDATE audit_events SET detail = 'manomesso' WHERE id = :i"),
            {"i": evento_id},
        )
    assert sqlstate(errore.value) == "HM403"
    db.rollback()


def test_delete_su_audit_events_rifiutato(db: Session) -> None:
    evento_id = _evento(db)
    db.commit()
    with pytest.raises(DBAPIError) as errore:
        db.execute(text("DELETE FROM audit_events WHERE id = :i"), {"i": evento_id})
    assert sqlstate(errore.value) == "HM403"
    db.rollback()


def test_truncate_su_audit_events_rifiutato(db: Session) -> None:
    with pytest.raises(DBAPIError) as errore:
        db.execute(text("TRUNCATE audit_events"))
    assert sqlstate(errore.value) == "HM403"
    db.rollback()


def test_tool_call_eseguita_senza_autorizzazione_rifiutata(db: Session) -> None:
    """Un'esecuzione riuscita senza autorizzazione tracciata non e' dichiarabile."""
    with pytest.raises(IntegrityError):
        db.execute(
            text(
                """
                INSERT INTO audit_events (correlation_id, event_type, outcome,
                                          authorized_by)
                VALUES (gen_random_uuid(), 'tool_call', 'ok', 'none')
                """
            )
        )
    db.rollback()


def test_evento_non_di_invocazione_non_richiede_autorizzazione(db: Session) -> None:
    """Il vincolo vale per `tool_call`: gli altri eventi non passano dal gate."""
    db.execute(
        text(
            """
            INSERT INTO audit_events (correlation_id, event_type, outcome, detail)
            VALUES (gen_random_uuid(), 'tool_registered', 'ok', 'registrazione')
            """
        )
    )
    db.commit()


# --------------------------------------------------------------------------- #
# Perimetro dei bersagli
# --------------------------------------------------------------------------- #


@pytest.mark.usefixtures("perimetro_pulito")
def test_cidr_in_forma_canonica_accettata(db: Session) -> None:
    db.execute(
        text("INSERT INTO scope_networks (cidr, label) VALUES ('192.168.205.0/24', 'Lab')")
    )
    db.commit()


@pytest.mark.usefixtures("perimetro_pulito")
def test_cidr_con_bit_host_rifiutata(db: Session) -> None:
    """192.168.205.10/24 verrebbe letto come l'intera /24.

    E' un perimetro diverso da quello che chi scrive crede di dichiarare, ed
    e' piu' largo: esattamente il difetto che questa validazione esiste per
    evitare. Il tipo `cidr` di PostgreSQL lo rifiuta da solo.
    """
    with pytest.raises(DBAPIError):
        db.execute(
            text(
                "INSERT INTO scope_networks (cidr, label) "
                "VALUES ('192.168.205.10/24', 'Sbagliata')"
            )
        )
    db.rollback()


@pytest.mark.usefixtures("perimetro_pulito")
def test_alias_dentro_una_rete_dichiarata_accettato(db: Session) -> None:
    db.execute(
        text("INSERT INTO scope_networks (cidr, label) VALUES ('192.168.205.0/24', 'Lab')")
    )
    db.execute(
        text("INSERT INTO scope_aliases (name, address) VALUES ('lab-web', '192.168.205.20')")
    )
    db.commit()


@pytest.mark.usefixtures("perimetro_pulito")
def test_alias_fuori_dalle_reti_rifiutato(db: Session) -> None:
    """Un alias fuori perimetro renderebbe il perimetro contraddittorio."""
    db.execute(
        text("INSERT INTO scope_networks (cidr, label) VALUES ('192.168.205.0/24', 'Lab')")
    )
    db.commit()
    with pytest.raises(DBAPIError) as errore:
        db.execute(
            text("INSERT INTO scope_aliases (name, address) VALUES ('fuori', '10.0.0.5')")
        )
    assert sqlstate(errore.value) == "HM422"
    db.rollback()


@pytest.mark.usefixtures("perimetro_pulito")
def test_alias_senza_nessuna_rete_rifiutato(db: Session) -> None:
    """Perimetro vuoto non vale «tutto ammesso»."""
    with pytest.raises(DBAPIError) as errore:
        db.execute(
            text("INSERT INTO scope_aliases (name, address) VALUES ('orfano', '10.0.0.5')")
        )
    assert sqlstate(errore.value) == "HM422"
    db.rollback()


@pytest.mark.usefixtures("perimetro_pulito")
def test_rimozione_rete_con_alias_dipendenti_rifiutata(db: Session) -> None:
    """Secondo modo di violare l'invariante: togliere la rete, non l'alias.

    Coprire solo l'inserimento lascerebbe questa come via d'uscita, ed e' la
    piu' facile da imboccare per sbaglio.
    """
    db.execute(
        text("INSERT INTO scope_networks (cidr, label) VALUES ('192.168.205.0/24', 'Lab')")
    )
    db.execute(
        text("INSERT INTO scope_aliases (name, address) VALUES ('lab-web', '192.168.205.20')")
    )
    db.commit()
    with pytest.raises(DBAPIError) as errore:
        db.execute(text("DELETE FROM scope_networks WHERE cidr = '192.168.205.0/24'"))
    assert sqlstate(errore.value) == "HM422"
    db.rollback()


@pytest.mark.usefixtures("perimetro_pulito")
def test_rimozione_rete_senza_alias_dipendenti_accettata(db: Session) -> None:
    db.execute(
        text("INSERT INTO scope_networks (cidr, label) VALUES ('192.168.205.0/24', 'Lab')")
    )
    db.commit()
    db.execute(text("DELETE FROM scope_networks WHERE cidr = '192.168.205.0/24'"))
    db.commit()


@pytest.mark.usefixtures("perimetro_pulito")
def test_restringere_una_rete_che_esclude_un_alias_rifiutato(db: Session) -> None:
    """Non solo la rimozione: anche restringere la maschera esclude un alias."""
    db.execute(
        text("INSERT INTO scope_networks (cidr, label) VALUES ('192.168.0.0/16', 'Lab')")
    )
    db.execute(
        text("INSERT INTO scope_aliases (name, address) VALUES ('lab-web', '192.168.205.20')")
    )
    db.commit()
    with pytest.raises(DBAPIError) as errore:
        db.execute(
            text("UPDATE scope_networks SET cidr = '192.168.1.0/24' WHERE cidr = '192.168.0.0/16'")
        )
    assert sqlstate(errore.value) == "HM422"
    db.rollback()


# --------------------------------------------------------------------------- #
# Vocabolari e altri vincoli
# --------------------------------------------------------------------------- #


def test_tier_ordinato_dal_database(db: Session) -> None:
    """L'ordinamento dell'ENUM e' cio' su cui si regge la monotonia."""
    assert db.execute(text("SELECT 'verde'::tier < 'giallo'::tier")).scalar_one()
    assert db.execute(text("SELECT 'giallo'::tier < 'rosso'::tier")).scalar_one()
    assert db.execute(text("SELECT max(t) FROM (VALUES ('verde'::tier), ('rosso'::tier)) s(t)")).scalar_one() == "rosso"


def test_agente_fuori_vocabolario_rifiutato(db: Session) -> None:
    with pytest.raises(DBAPIError):
        db.execute(
            text(
                """
                INSERT INTO tools (tool_id, agent, declared_tier, personal_data,
                                   exec_path, exec_sha256, description)
                VALUES ('prova.inventato', 'agente_inventato', 'verde', false,
                        'a.py',
                        '34b7aa6afc7f96e5c88ecfd8f4305a0739743bc5a1f7aa27ee2b63546518d3a8',
                        'x')
                """
            )
        )
    db.rollback()


@pytest.mark.parametrize(
    "exec_path",
    ["/etc/passwd", "../fuori/run.py", "agents/../../etc/run.py", ""],
)
def test_exec_path_non_confinato_rifiutato(db: Session, exec_path: str) -> None:
    """Un percorso assoluto o con '..' aggirerebbe il pinning via SHA."""
    with pytest.raises(IntegrityError):
        db.execute(
            text(
                """
                INSERT INTO tools (tool_id, agent, declared_tier, personal_data,
                                   exec_path, exec_sha256, description)
                VALUES ('prova.percorso', 'vuln_assessment', 'verde', false,
                        :p,
                        '34b7aa6afc7f96e5c88ecfd8f4305a0739743bc5a1f7aa27ee2b63546518d3a8',
                        'x')
                """
            ),
            {"p": exec_path},
        )
    db.rollback()


@pytest.mark.parametrize(
    "sha",
    ["non-uno-sha", "ABCDEF" + "0" * 58, "0" * 63, "0" * 65],
)
def test_sha256_malformato_rifiutato(db: Session, sha: str) -> None:
    """Un valore che non sia 64 esadecimali minuscoli non pinna niente."""
    with pytest.raises(IntegrityError):
        db.execute(
            text(
                """
                INSERT INTO tools (tool_id, agent, declared_tier, personal_data,
                                   exec_path, exec_sha256, description)
                VALUES ('prova.sha', 'vuln_assessment', 'verde', false,
                        'a.py', :s, 'x')
                """
            ),
            {"s": sha},
        )
    db.rollback()


def test_consenso_che_scade_prima_di_essere_dato_rifiutato(db: Session) -> None:
    with pytest.raises(IntegrityError):
        db.execute(
            text(
                """
                INSERT INTO scope_consents (agent, scope, granted_by,
                                            granted_at, expires_at)
                VALUES ('pentest_kali', '192.168.205.0/24', 'test',
                        now(), now() - interval '1 day')
                """
            )
        )
    db.rollback()


def test_hash_password_non_argon2_rifiutato(db: Session) -> None:
    """Impedisce che una password in chiaro finisca nella colonna dell'hash."""
    with pytest.raises(IntegrityError):
        db.execute(
            text(
                "INSERT INTO users (username, password_hash) "
                "VALUES ('tizio', 'password-in-chiaro')"
            )
        )
    db.rollback()
