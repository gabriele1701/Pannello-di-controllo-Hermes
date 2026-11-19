# NOTICE — strumenti di terze parti usati dal VSPT

Il VSPT **non** include il codice di questi strumenti nel repo: li installa da
upstream al build dell'immagine (`assess/Dockerfile`), a versioni pinnate.
Questo file elenca ciascuno con la sua versione e la sua licenza. Il codice di
`assess/` resta sotto la licenza del repo (vedi `LICENSE` in radice).

| Strumento   | Versione pinnata | Licenza     | Upstream |
|-------------|------------------|-------------|----------|
| nuclei      | 3.3.7            | MIT         | github.com/projectdiscovery/nuclei |
| sqlmap      | 1.8.11           | GPL-2.0     | github.com/sqlmapproject/sqlmap |
| semgrep     | 1.97.0           | LGPL-2.1    | github.com/semgrep/semgrep |
| pip-audit   | 2.7.3            | Apache-2.0  | github.com/pypa/pip-audit |

Le versioni qui devono coincidere con quelle del `Dockerfile` e con
`assess/runner.py` (`PIN_TOOL`): sono la stessa affermazione in tre punti, e i
metadati di ogni report le dichiarano.

## Testi completi delle licenze

Il testo integrale di ciascuna licenza si recupera dal rispettivo upstream alla
versione pinnata e si deposita qui accanto a questo NOTICE (un file per
strumento) al momento del lock delle versioni, prima della consegna. Non sono
incollati ora per non versionare un testo di licenza non verificato contro la
release reale.

## Nota di compatibilita'

GPL-2.0 (sqlmap) e LGPL-2.1 (semgrep) sono licenze copyleft. Qui gli strumenti
sono **invocati come processi separati** (eseguibili a se'), non linkati nel
codice di `assess/`: il tool li usa, non li incorpora. Questo tiene il codice
di `assess/` sotto la licenza del repo senza che il copyleft lo contagi. Da
riverificare se un domani si linkasse una libreria di uno di questi progetti
invece di eseguirne il binario.

## Strumenti rinviati (roadmap)

katana, ffuf, arjun, trivy non sono nell'MVP. Quando entrano, ciascuno va
aggiunto qui con versione e licenza (ffuf/katana MIT; arjun: da confermare al
momento dell'inclusione).
