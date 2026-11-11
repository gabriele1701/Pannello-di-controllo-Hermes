"""Configurazione dell'applicazione, letta dall'ambiente.

Nessun valore di default per i segreti. Un default funzionante per una
password o per una chiave di firma e' un default che sopravvive al
dispiegamento: resta quello, nessuno lo cambia, e diventa una credenziale
nota a chiunque abbia letto il repository. Qui l'assenza fa fallire l'avvio
con un messaggio che dice cosa manca.

Le variabili non segrete — nome utente del database, ambiente — hanno un
default, perche' conoscerle non da' accesso a niente.

DUE CONFIGURAZIONI, NON UNA
---------------------------

`Settings` e' la configurazione di cio' che **serve richieste**: l'URL del
ruolo applicativo, la chiave di firma del cookie, la durata della sessione.

`ImpostazioniPrivilegiate` e' quella di cio' che **modifica lo schema**:
migrazioni e seed, che girano con il ruolo proprietario.

Sono separate perche' hanno bisogni disgiunti, e tenerle insieme faceva
pagare al seed dei requisiti che non sono suoi: `python -m backend.seed`
pretendeva `DATABASE_URL` e `APP_SECRET_KEY` — una chiave di firma, in un
programma che non serve nessuna richiesta e non firma nessun cookie — solo
perche' passava da `Settings`. Chi lo eseguiva a mano doveva inventarsi due
valori per soddisfare un controllo, che e' il modo in cui un controllo
diventa un rito.

`migrations/env.py` leggeva gia' l'ambiente da se', per la stessa ragione.
Questa classe gli da' un posto invece di lasciarlo un caso a parte.
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
            "URL SQLAlchemy con cui l'applicazione in esercizio si connette. "
            "Punta al ruolo `hermes_app`, che non possiede le tabelle e quindi "
            "non puo' disabilitarne i trigger. Obbligatorio."
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


class ImpostazioniPrivilegiate(BaseSettings):
    """Cio' che serve a migrazioni e seed, e nient'altro.

    Nessuna chiave di firma e nessuna durata di sessione: un programma che
    scrive tabelle e poi esce non ha sessioni da firmare. Dichiarare qui
    soltanto cio' che si usa fa fallire l'avvio per le ragioni vere.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    migrations_database_url: str | None = Field(
        default=None,
        alias="MIGRATIONS_DATABASE_URL",
    )

    #: Ripiego, non alternativa: vedi `url`.
    database_url: str | None = Field(default=None, alias="DATABASE_URL")

    @property
    def url(self) -> str:
        """URL del ruolo con cui girano migrazioni e seed.

        Con `MIGRATIONS_DATABASE_URL` assente ricade su `DATABASE_URL`, che
        e' una comodita' per lo sviluppo locale dove spesso esiste un solo
        ruolo -- **non** una configurazione valida in esercizio. Il compose
        imposta le due URL distinte, quindi in un dispiegamento il ripiego
        non si verifica.

        L'ordine e' quello: prima la privilegiata. Invertirlo significherebbe
        far girare le migrazioni con il ruolo applicativo, che non possiede
        le tabelle e non potrebbe modificarle -- con un errore sui permessi
        invece di uno sulla configurazione.
        """
        url = self.migrations_database_url or self.database_url
        if not url:
            raise RuntimeError(
                "Ne' MIGRATIONS_DATABASE_URL ne' DATABASE_URL sono "
                "impostate: migrazioni e seed non sanno a quale database "
                "connettersi.\n"
                "\n"
                "  export MIGRATIONS_DATABASE_URL="
                "postgresql+psycopg://proprietario:...@localhost:5432/hermes_panel"
            )
        return url


@lru_cache(maxsize=1)
def get_impostazioni_privilegiate() -> ImpostazioniPrivilegiate:
    """Impostazioni del ruolo proprietario, lette una volta sola."""
    return ImpostazioniPrivilegiate()  # type: ignore[call-arg]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Impostazioni, lette una volta sola.

    La cache non e' un'ottimizzazione: e' la garanzia che l'applicazione non
    cambi configurazione a meta' del proprio ciclo di vita.
    """
    return Settings()  # type: ignore[call-arg]
