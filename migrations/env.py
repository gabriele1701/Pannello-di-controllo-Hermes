"""Ambiente Alembic.

L'URL del database arriva dall'ambiente, non da ``alembic.ini``: scriverlo nel
file di configurazione significherebbe versionare la password del database.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

_url = os.environ.get("DATABASE_URL")
if not _url:
    raise RuntimeError(
        "DATABASE_URL non impostata: le migrazioni non sanno su quale "
        "database girare. In locale: export DATABASE_URL=postgresql+psycopg://..."
    )
config.set_main_option("sqlalchemy.url", _url)

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
