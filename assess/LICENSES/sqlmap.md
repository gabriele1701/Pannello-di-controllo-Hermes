# sqlmap — licenza

- **Strumento:** sqlmap
- **Versione pinnata:** 1.8.11
- **Licenza:** GNU General Public License v2.0 (SPDX: `GPL-2.0-only`)
- **Copyright:** (c) 2006-2024 Bernardo Damele Assumpcao Guimaraes, Miroslav Stampar
- **Upstream:** https://github.com/sqlmapproject/sqlmap
- **File di licenza upstream:** `LICENSE` nella repo, tag `1.8.11`

sqlmap e' distribuito sotto **GPL-2.0**. Il testo integrale della GPL-2.0 e' il
documento canonico SPDX `GPL-2.0-only` (https://spdx.org/licenses/GPL-2.0-only.html),
identico per tutti i progetti che la adottano; sqlmap aggiunge la propria
intestazione di copyright (sopra) in testa ai sorgenti.

Uso nel VSPT: invocato come **processo separato** (eseguibile a se'), **non**
linkato ne' incorporato nel codice di `assess/`. Il copyleft GPL non si estende
quindi al codice dell'assessor. Da riverificare se un domani se ne linkasse una
libreria invece di eseguirne il binario.
