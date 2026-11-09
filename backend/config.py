"""Configurazione dell'applicazione, letta dall'ambiente.

Nessun valore di default per i segreti. Un default funzionante per una
password o per una chiave di firma e' un default che sopravvive al
dispiegamento: resta quello, nessuno lo cambia, e diventa una credenziale
nota a chiunque abbia letto il repository. Qui l'assenza fa fallire l'avvio
con un messaggio che dice cosa manca.

Le variabili non segrete — nome utente del database, ambiente — hanno un
default, perche' conoscerle non da' accesso a niente.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Impostazioni dell'applicazione."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- database ----------------------------------------------------------- #

    database_url: str = Field(
        alias="DATABASE_URL",
        description=(
            "URL SQLAlchemy del database. Obbligatorio: senza, l'applicazione "
            "non sa dove sta il proprio stato."
        ),
    )

    # -- sessione ----------------------------------------------------------- #

    secret_key: SecretStr = Field(
        alias="APP_SECRET_KEY",
        description=(
            "Chiave di firma del cookie di sessione. Obbligatoria: con una "
            "chiave prevedibile un cookie di sessione si forgia a mano."
        ),
    )

    app_env: Literal["development", "production"] = Field(
        default="development",
        alias="APP_ENV",
    )

    #: Durata della sessione. Una sessione che non scade non e' una sessione.
    session_max_age_seconds: int = Field(default=8 * 3600, alias="APP_SESSION_MAX_AGE")

    # -- operatore iniziale ------------------------------------------------- #

    admin_username: str = Field(default="operatore", alias="HERMES_ADMIN_USERNAME")
    admin_password: SecretStr | None = Field(default=None, alias="HERMES_ADMIN_PASSWORD")

    @field_validator("secret_key")
    @classmethod
    def _chiave_non_banale(cls, v: SecretStr) -> SecretStr:
        """Rifiuta una chiave troppo corta o lasciata al valore d'esempio.

        Il controllo sulla lunghezza non e' pedanteria: una chiave di 8
        caratteri si attacca a forza bruta fuori linea, e il risultato e' un
        cookie di sessione valido per l'unico account del pannello.
        """
        valore = v.get_secret_value()
        if len(valore) < 32:
            raise ValueError(
                "APP_SECRET_KEY deve essere lunga almeno 32 caratteri. "
                "Generarla con: openssl rand -hex 32"
            )
        if valore.startswith("sostituiscimi"):
            raise ValueError(
                "APP_SECRET_KEY e' ancora il valore d'esempio di .env.example. "
                "Generarne una con: openssl rand -hex 32"
            )
        return v

    @property
    def cookie_secure(self) -> bool:
        """Se il cookie di sessione va marcato ``Secure``.

        Attivo in produzione, dove il traffico passa da HTTPS. In sviluppo
        resta disattivo, altrimenti il browser non invierebbe mai il cookie
        su ``http://localhost`` e il login non funzionerebbe.
        """
        return self.app_env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Impostazioni, lette una volta sola.

    La cache non e' un'ottimizzazione: e' la garanzia che l'applicazione non
    cambi configurazione a meta' del proprio ciclo di vita.
    """
    return Settings()  # type: ignore[call-arg]
