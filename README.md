 🛡️ Bastion Guard (safe-code-audit)

**Bastion Guard** is a high-performance security and privacy plugin for [Claude Code](https://code.claude.com). Powered by the **Bastion Audit** engine, it provides a "Zero-Trust" layer for developers working in sensitive environments like Financial Services, Insurance, and Healthcare.

[![Claude Code Compatible](https://img.shields.io/badge/Claude%20Code-Compatible-green)](https://code.claude.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Security: Enterprise](https://img.shields.io/badge/Security-Enterprise--Grade-red)](#)

## 🚀 Overview

AI agents are powerful, but they often lack context regarding data privacy (PII) and industry-specific security compliance. **Bastion Guard** acts as an invisible shield, intercepting commands and file writes before they leave your terminal.

### Key Features
* **Real-time PII Detection:** Automatically flags and masks Emails, API Keys, and Canadian SINs before they are sent to the LLM.
* **Pre-Flight Interception:** Uses `PreToolUse` hooks to stop dangerous `bash` or `write` commands before they execute.
* **Financial Grade Guardrails:** Specialized patterns for high-compliance industries.
* **Automated Audit Trails:** Generates a `SECURITY_AUDIT.md` report for every session to satisfy internal compliance requirements.

## 🛠️ Installation

Inside your Claude Code terminal, run:

```bash
/plugin add [github.com/your-username/bastion-guard](https://github.com/your-username/bastion-guard)
