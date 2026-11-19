"""Wrapper dei canali verso il target. Interfaccia del tool, non controllo di
sicurezza: il minimo privilegio reale sta sul server (SSH ``restrict`` +
``ForceCommand`` validatore, ruolo DB ``hermes_assess`` SELECT-only)."""
