"""Motore e sessioni SQLAlchemy.

La sessione e' fornita come dipendenza FastAPI con ``commit`` esplicito al
termine del gestore e ``rollback`` su eccezione. Non c'e' autocommit: le
rotte che scrivono devono dichiararlo, perche' in questa applicazione quasi
tutte le scritture passano per un vincolo di integrita' che puo' rifiutarle,
e un commit implicito maschererebbe il punto in cui il rifiuto accade.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.config import get_settings


class Base(DeclarativeBase):
    """Base dichiarativa dei modelli."""


def _crea_engine():
    impostazioni = get_settings()
    return create_engine(
        impostazioni.database_url,
        # pool_pre_ping: una connessione nel pool puo' essere stata chiusa dal
        # server (riavvio del container db). Senza, la prima richiesta dopo un
        # riavvio fallirebbe con un errore opaco.
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        future=True,
    )


_engine = None
_SessionLocal: sessionmaker[Session] | None = None


def engine():
    """Motore condiviso, creato alla prima richiesta."""
    global _engine
    if _engine is None:
        _engine = _crea_engine()
    return _engine


def session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=engine(),
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
            future=True,
        )
    return _SessionLocal


def get_db() -> Iterator[Session]:
    """Dipendenza FastAPI: una sessione per richiesta."""
    db = session_factory()()
    try:
        yield db
    finally:
        db.close()
