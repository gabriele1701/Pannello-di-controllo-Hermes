"""Parser di ``openapi.json`` → inventario di endpoint e parametri.

Serve ai collector esterni (nuclei, sqlmap): quali URL esistono, quali
parametri accettano, quali di questi sono candidati all'iniezione. La fonte e'
il contratto committato, non una lista scritta a mano che divergerebbe.

Cosa estrae, e cosa no
----------------------

Per ogni operazione: metodo, path, parametri separati per posizione
(``path`` / ``query`` / ``cookie`` / ``header``) e i campi del corpo della
richiesta, risolvendo un ``$ref`` a ``components/schemas`` di un livello.

Il cookie di sessione (``hermes_session``) e' marcato come autenticazione, non
come parametro iniettabile: un fuzzer che lo mutasse starebbe testando il
login, non l'endpoint. ``parametri_iniettabili`` esclude i cookie proprio per
questo.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: Nome del cookie di sessione del pannello. Non e' un bersaglio di injection.
COOKIE_SESSIONE = "hermes_session"

_METODI = ("get", "post", "put", "patch", "delete")


@dataclass(slots=True)
class Endpoint:
    """Un'operazione del contratto."""

    method: str
    path: str
    path_params: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    cookie_params: list[str] = field(default_factory=list)
    header_params: list[str] = field(default_factory=list)
    body_fields: list[str] = field(default_factory=list)

    @property
    def richiede_auth(self) -> bool:
        """Vero se l'operazione richiede il cookie di sessione."""
        return COOKIE_SESSIONE in self.cookie_params

    @property
    def parametri_iniettabili(self) -> list[str]:
        """Parametri candidati all'iniezione: path, query e campi del corpo.

        Esclude i cookie (il cookie di sessione non e' un bersaglio di
        injection). E' la lista che sqlmap riceverebbe per questo endpoint."""
        return [*self.path_params, *self.query_params, *self.body_fields]

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


def carica_openapi(percorso: str | Path) -> dict[str, Any]:
    """Carica e parsa il documento OpenAPI da file."""
    return json.loads(Path(percorso).read_text(encoding="utf-8"))


def _risolvi_ref(doc: dict[str, Any], ref: str) -> dict[str, Any]:
    """Risolve un ``$ref`` locale (``#/components/...``) nel documento.

    Solo riferimenti locali: un ``$ref`` esterno in un contratto che si vuole
    autoconsistente sarebbe un errore da far emergere, non da seguire in
    rete."""
    if not ref.startswith("#/"):
        raise ValueError(f"$ref non locale non supportato: {ref!r}")
    nodo: Any = doc
    for parte in ref.removeprefix("#/").split("/"):
        # Le chiavi JSON Pointer escapano ~1 -> / e ~0 -> ~
        parte = parte.replace("~1", "/").replace("~0", "~")
        if not isinstance(nodo, dict) or parte not in nodo:
            raise ValueError(f"$ref irrisolvibile: {ref!r} (manca {parte!r})")
        nodo = nodo[parte]
    if not isinstance(nodo, dict):
        raise ValueError(f"$ref non punta a un oggetto: {ref!r}")
    return nodo


def _schema_deref(doc: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Se lo schema e' un ``$ref``, lo risolve una volta; altrimenti lo
    restituisce com'e'."""
    if "$ref" in schema:
        return _risolvi_ref(doc, schema["$ref"])
    return schema


def _campi_corpo(doc: dict[str, Any], operazione: dict[str, Any]) -> list[str]:
    """Nomi dei campi del corpo JSON della richiesta, se presente.

    Risolve un ``$ref`` di primo livello e legge ``properties``. Non scende nei
    sotto-oggetti: la superficie che interessa a un fuzzer e' quella dei campi
    di primo livello, e scendere ricorsivamente in uno schema annidato darebbe
    nomi che non corrispondono a parametri di richiesta."""
    body = operazione.get("requestBody")
    if not isinstance(body, dict):
        return []
    body = _schema_deref(doc, body)
    contenuto = body.get("content", {})
    media = contenuto.get("application/json") or next(iter(contenuto.values()), None)
    if not isinstance(media, dict) or "schema" not in media:
        return []
    schema = _schema_deref(doc, media["schema"])
    proprieta = schema.get("properties")
    if not isinstance(proprieta, dict):
        return []
    return list(proprieta.keys())


def _parametri(
    doc: dict[str, Any], operazione: dict[str, Any], comuni: list[Any]
) -> dict[str, list[str]]:
    """Raccoglie i parametri per posizione (``in``), fondendo quelli comuni al
    path con quelli dell'operazione e risolvendo eventuali ``$ref``."""
    per_posizione: dict[str, list[str]] = {
        "path": [],
        "query": [],
        "cookie": [],
        "header": [],
    }
    for voce in [*comuni, *operazione.get("parameters", [])]:
        if isinstance(voce, dict) and "$ref" in voce:
            voce = _risolvi_ref(doc, voce["$ref"])
        if not isinstance(voce, dict):
            continue
        posizione = voce.get("in")
        nome = voce.get("name")
        if posizione in per_posizione and isinstance(nome, str):
            if nome not in per_posizione[posizione]:
                per_posizione[posizione].append(nome)
    return per_posizione


def inventario(doc: dict[str, Any]) -> list[Endpoint]:
    """Lista di tutti gli endpoint del contratto, in ordine stabile."""
    endpoints: list[Endpoint] = []
    paths = doc.get("paths", {})
    for path, operazioni in paths.items():
        if not isinstance(operazioni, dict):
            continue
        comuni = operazioni.get("parameters", [])
        for metodo, operazione in operazioni.items():
            if metodo.lower() not in _METODI or not isinstance(operazione, dict):
                continue
            params = _parametri(doc, operazione, comuni)
            endpoints.append(
                Endpoint(
                    method=metodo.upper(),
                    path=path,
                    path_params=params["path"],
                    query_params=params["query"],
                    cookie_params=params["cookie"],
                    header_params=params["header"],
                    body_fields=_campi_corpo(doc, operazione),
                )
            )
    return endpoints


def inventario_da_file(percorso: str | Path) -> list[Endpoint]:
    """Comodita': carica il file e restituisce l'inventario."""
    return inventario(carica_openapi(percorso))


__all__ = [
    "COOKIE_SESSIONE",
    "Endpoint",
    "carica_openapi",
    "inventario",
    "inventario_da_file",
]
