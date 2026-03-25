# BastionAudit: Enterprise Security & Compliance Dashboard

BastionAudit is a high-performance, AI-powered security auditing and compliance monitoring dashboard specifically designed for the **Canadian Financial Services Industry**. It provides real-time visibility into system activities, PII detection, and regulatory adherence (OSFI, PIPEDA, FINTRAC).

## 🚀 Key Features

### 🛡️ Real-Time Security Engine
- **Intercept & Audit:** Monitors system-level commands and file modifications in real-time.
- **Alert Terminal:** Interactive overlay for immediate threat response and remediation.
- **Plugin Architecture:** Extensible security rules and PII detectors.

### 🇨🇦 Canadian Compliance Suite
- **OSFI B-10/B-13 Monitoring:** Specialized tracking for third-party risk and technology resilience.
- **PIPEDA Privacy Guard:** Automated detection of Canadian PII (SIN, Provincial IDs, Health Cards).
- **FINTRAC AML Hooks:** Integration points for anti-money laundering reporting.
- **Data Residency Guard:** Ensures sensitive financial data remains within Canadian borders.

### 🤖 Dual-Engine AI Assistant
- **Claude 3.5 Sonnet:** Primary high-reasoning security assistant.
- **Gemini 3.1 Pro:** High-performance fallback engine for uninterrupted service.
- **Context-Aware:** Understands your specific infrastructure and compliance posture.

### 🌑 Modern Dark Interface
- **High-Contrast Design:** Optimized for security operations centers (SOC).
- **Bento-Grid Layout:** Scannable metrics and dense information display.
- **Interactive Visualizations:** Real-time throughput and latency tracking.

## 🛠️ Tech Stack

- **Frontend:** React 18, Vite, Tailwind CSS, Framer Motion, Lucide Icons.
- **Backend:** Express.js (Secure API Proxy).
- **AI Integration:** Anthropic SDK (Claude), Google Generative AI SDK (Gemini).
- **Deployment:** Optimized for Cloud Run and containerized environments.

## 🚦 Getting Started

### Prerequisites
- Node.js 18+
- Anthropic API Key (for Claude)
- Google AI Studio API Key (for Gemini)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/bastion-audit.git
   cd bastion-audit
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Create a `.env` file in the root directory:
   ```env
   CLAUDE_API_KEY=your_claude_key
   GEMINI_API_KEY=your_gemini_key
   ```

4. **Start the development server:**
   ```bash
   npm run dev
   ```

## 📋 Compliance Standards Supported
- **OSFI B-10:** Third-Party Risk Management.
- **OSFI B-13:** Technology and Cyber Risk Management.
- **PIPEDA:** Personal Information Protection and Electronic Documents Act.
- **FINTRAC:** Financial Transactions and Reports Analysis Centre of Canada.
- **SOC2 Type II:** Security, Availability, Processing Integrity, Confidentiality, and Privacy.

## 🤝 Contributing
We welcome contributions from the security community. Please see `CONTRIBUTING.md` for guidelines.

## 📄 License
This project is licensed under the MIT License - see the `LICENSE` file for details.

---
*Built for the future of Canadian Financial Security.*
