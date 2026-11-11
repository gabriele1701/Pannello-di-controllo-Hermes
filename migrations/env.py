"""Ambiente Alembic.

L'URL del database arriva dall'ambiente, non da ``alembic.ini``: scriverlo nel
file di configurazione significherebbe versionare la password del database.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from backend.config import get_impostazioni_privilegiate

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# L'URL arriva dalla configurazione privilegiata, non da `os.environ` letto
# qui: la regola «MIGRATIONS_DATABASE_URL prima di DATABASE_URL» e il suo
# messaggio d'errore esistevano in due copie, una qui e una in
# backend/config.py, ed era questione di tempo prima che una cambiasse senza
# l'altra. La regola in se' resta quella: le migrazioni devono girare con il
# ruolo PROPRIETARIO delle tabelle. Il ruolo applicativo non possiede niente
# -- e' il punto della separazione -- quindi un `alembic upgrade head` con
# quello fallirebbe al primo CREATE.
config.set_main_option("sqlalchemy.url", get_impostazioni_privilegiate().url)

# Le migrazioni di questo progetto sono scritte a mano, non generate.
# `autogenerate` non sa produrre i trigger e le funzioni che reggono gli
# invarianti del dominio, e uno schema in cui i vincoli sono parzialmente
# generati e parzialmente scritti e' uno schema in cui non si sa cosa sia
# applicato davvero. target_metadata resta None di proposito.
target_metadata = None


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
