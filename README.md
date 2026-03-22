# 🛡️ Bastion Guard (safe-code-audit)

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

🕹️ How it WorksBastion Guard operates at the Middleware Layer. When Claude attempts to use a tool (like writing to a file), the plugin intercepts the content:Intercept: The security-check.js hook captures the proposed tool parameters.Scan: The Bastion Audit engine runs high-speed regex and entropy checks.Action: * Green: No threats detected. The command proceeds.Red: Threat detected. The process is blocked, and an ANSI-colored alert is shown in your terminal.⚙️ ConfigurationUse the built-in skill to customize your security posture:"Claude, set Bastion Guard to high-strictness mode."Available modes:Default: Standard PII and credential scanning.Financial: Enhanced monitoring for account numbers and transaction patterns.Red-Team: Detects potential prompt injection or jailbreak attempts.📊 Security Audit LogAt the end of your session, Bastion Guard produces a summary:TimestampEvent TypeAction TakenLogic Engine14:02:11PII Detected (Email)RedactedBastion Core14:15:45Secret Key (AWS)BlockedBastion Entropy🤝 ContributingWe welcome contributions from the security community! If you are interested in adding new guardrail patterns, please see our CONTRIBUTING.md.📄 LicenseDistributed under the MIT License. See LICENSE for more information.Built with ❤️ in Toronto for the global developer community.
