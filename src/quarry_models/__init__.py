"""Quarry model layer: safe prompt construction, redaction, and model clients.

All target-controlled content is treated as untrusted evidence. Redaction is the
single chokepoint through which content passes before it can enter a prompt, and
all model access goes through the ``ModelClient`` interface.
"""
