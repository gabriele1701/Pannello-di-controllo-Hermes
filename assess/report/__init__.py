"""Report dell'assessment: JSON canonico e HTML.

La divisione e' netta e voluta: ``json_report`` costruisce il documento (la
valutazione sta tutta qui e a monte, nei finding gia' calcolati);
``html_report`` rende **soltanto** a partire da quel JSON, senza una riga di
logica di valutazione. L'HTML e' una vista del JSON, non una seconda fonte di
verita' che potrebbe divergere.
"""
