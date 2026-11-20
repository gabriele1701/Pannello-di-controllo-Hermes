"""Canale SSH dell'assessor: il contratto a verbi logici.

Il controllo di sicurezza vero e' il ForceCommand ``vspt-ssh-wrapper``,
installato e testato sulla VM: ``sshd`` lo invoca per ogni connessione
dell'utente ``assess``, legge ``$SSH_ORIGINAL_COMMAND`` come **stringa-verbo
esatta** (mai shell), la confronta con l'allowlist dei verbi e risponde con un
**envelope JSON** su una riga. Il contratto condiviso e' in ``PROTOCOL.md``.

``vspt-ssh-wrapper`` in questo repo e' byte-identico a quello sulla VM (la VM e'
la fonte di verita', il repo la segue): non va modificato da qui.
"""
