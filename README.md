# 🛡️ Sentinel Shield AI Security architecture

Enterprise-level AI agent featuring a robust 4-Layer Threat Detection Pipeline, True Enterprise RAG, and a live SecOps Telemetry Dashboard.

## 🚀 Features

### 🔍 **4-Layer Threat Detection Engine (AI Firewall)**
- **Layer 1: Heuristic Regex:** High-speed blocking of known jailbreak macros.
- **Layer 2: Semantic LLM Judge:** Llama-3-8B dynamically scores prompt intent to prevent obfuscated attacks.
- **Layer 3: Execution Sandboxing:** Tool parameters (like URLs) are validated, and outputs are sanitized to block Indirect Prompt Injections.
- **Layer 4: Output Guardrails (DLP):** Final response scraping prevents internal system prompts or secrets from being leaked.

### 🧠 **3-Tier Enterprise Memory System**
- **Tier 1: Short-Term Working Memory:** Ultra-low latency Python state arrays hold the immediate 5-turn chat history.
- **Tier 2: Long-Term Episodic Memory:** At the click of a button, the entire session is summarized and archived into a ChromaDB vector database for future recall.
- **Tier 3: Enterprise RAG (Knowledge Base):** An independent ChromaDB collection securely houses internal corporate policies offline. The Agent independently navigates this data via a dedicated `query_knowledge_base` tool.

### 📊 **Live SecOps Telemetry Dashboard**
- **Streamlit Interface:** Modern, responsive chat UI and metrics viewer.
- **SQLite3 Integration:** Persistent relational SIEM logging of all allowed and blocked user actions.
- **Pandas Visualization:** Live rendering of agent interventions, complete with action distributions and threat logs.

### ⚡ **Autonomous ReAct Agent Loop**
- **Llama-3-70B Cognitive Engine:** The agent loops through `Thought -> Action -> Observation` paradigms to solve complex user tasks.
- **Groq LPU Hardware:** Token generation is streamed deterministicly with ultra-low Time-To-First-Token latency.
- **Tavily Web Search:** Integrated AI-optimized search queries.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Sentinel Shield Platform                 │
├─────────────────────────────────────────────────────────────┤
│  Frontend (Streamlit)                                       │
│  ├─ Interactive Agent Chat                                  │
│  └─ Live SecOps Dashboard (Pandas)                          │
├─────────────────────────────────────────────────────────────┤
│  Security Layer (AI Firewall)                               │
│  ├─ Heuristic Regular Expressions                           │
│  ├─ Semantic Auditor (Llama-3-8B)                           │
│  └─ Execution & Data DLP Filters                            │
├─────────────────────────────────────────────────────────────┤
│  Core Cognitive Engine                                      │
│  ├─ Multi-step Reasoning (Llama-3-70B)                      │
│  ├─ Web Search Integration (Tavily)                         │
│  └─ Stateful Python Execution (`eval()`)                    │
├─────────────────────────────────────────────────────────────┤
│  Memory & Data Layer                                        │
│  ├─ Telemetry Database (SQLite3)                            │
│  ├─ Episodic Session Storage (ChromaDB)                     │
│  └─ RAG Knowledge Base (ChromaDB)                           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Groq API Key
- Tavily API Key

### 1. Installation
Clone the repository and install the required dependencies (if using a virtual environment, activate it first).
```bash
git clone https://github.com/TejasM76/sentinel-shield.git
cd sentinel-shield
pip install streamlit pandas groq tavily-python chromadb bs4 python-dotenv requests
```

### 2. Environment Setup
Create a `.env` file in the root directory and add your API keys:
```env
GROQ_API_KEY=your_groq_api_key_here
TAVILY_API_KEY=your_tavily_api_key_here
```

### 3. Launching the Platform
Run the Streamlit server directly:
```bash
streamlit run agent_ui.py
```

*The application will automatically initialize the local `secops_telemetry.db` SQLite database and chunk the mock `corporate_policy.txt` into the ChromaDB Knowledge Base upon first launch.*

---

## 🛡️ Telemetry & Monitoring

All interaction data flows through the `security_layer.py(log_event)` hook and is recorded persistently in the local SQLite table: **secops_telemetry.db**.

This allows Security Operations (SecOps) teams to query the interaction logs entirely independent of the Streamlit application using standard standard SQL interfaces:
```sql
SELECT timestamp, event_type, action, details 
FROM security_events 
ORDER BY timestamp DESC;
```

---

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-security-layer`)
3. Commit your changes (`git commit -m 'Add new security layer'`)
4. Push to the branch (`git push origin feature/new-security-layer`)
5. Open a Pull Request

## 📄 License
This project is licensed under the MIT License.
