"""Native-dependency detection + assisted-install for the local scanner.

The scanner needs three external binaries to operate at full capability:
``nmap``, ``tshark`` (Wireshark CLI) and on Windows the ``Npcap`` capture
driver. None of them are bundled with the application — bundling Nmap or
Npcap would require commercial redistribution licenses we don't have. This
module instead helps the user install the official packages from upstream:

  * ``registry``   — declarative per-platform spec (URLs, SHA256, etc.).
  * ``detector``   — probes the live system to see what's already installed.
  * ``installer``  — downloads the official installer, verifies it, runs it.

The HTTP API surface is in ``server.py`` under ``/api/setup/*``; the wizard
UI lives in ``frontend/app/dashboard/setup``.
"""

from __future__ import annotations
