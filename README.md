# OASIS

**Open Architecture Security Interception Suite** (OASIS) is a fully open-source alternative to Burp Suite, featuring:

- HTTP/HTTPS interception powered by [mitmproxy](https://mitmproxy.org/).
- A **PyQt5** + **qasync** GUI for an always-on proxy, Repeater, Test Cases, Logger, and more.
- **Obsidian-like vault** approach for automatic state persistence (requests, config, etc.).

## Features
1. **Proxy**: Captures HTTP/HTTPS traffic in real time, using mitmproxy under the hood.
2. **Repeater**: Replay and modify requests with a raw HTTP editor, plus **undo/redo** history.
3. **State Manager**: Maintains a local JSON-based vault for storing requests, tabs, config, etc.
4. **Test & Logger Tabs**: Placeholders for deeper automation or event logging expansions.

## Quick Start
1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt

    Run OASIS:

python oasis.py

Configure Your Proxy (in browser/system settings):

    Host: 127.0.0.1
    Port: 8080
    For HTTPS, trust the mitmproxy CA cert (found in ~/.mitmproxy by default).
