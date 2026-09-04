# 🛡️ Onyx Packet Sniffer

A Python-based network threat detection system that captures live network traffic, flags suspicious activity using rule-based detection, and maps findings to the **MITRE ATT&CK** framework — visualized through a real-time **Streamlit** dashboard.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Scapy](https://img.shields.io/badge/Packet%20Capture-Scapy-orange)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red)
![License](https://img.shields.io/badge/License-MIT-green)

> Built as a hands-on cybersecurity project to practice network monitoring, threat detection logic, and attack framework mapping — from packet capture to visualization.

---

## 📸 Preview



---

## 🔍 What It Does

Onyx Packet Sniffer listens to live network traffic and flags potentially malicious activity in real time. Every detected event is:

- Captured directly off the wire using **Scapy**
- Checked against a set of **signature-based rules** (known bad ports, suspicious IPs, known malicious patterns)
- Tagged with the relevant **MITRE ATT&CK tactic/technique** for context
- Displayed on a live **Streamlit dashboard** for monitoring and review

This bridges raw packet capture with something a security analyst can actually *read and act on* — instead of a raw pcap dump.

---

## ✨ Features

- 📡 **Live packet capture** using Scapy
- 🚨 **Rule-based threat detection** (suspicious ports, known malicious IPs, traffic patterns)
- 🗺️ **MITRE ATT&CK mapping** for every flagged event
- 📊 **Real-time Streamlit dashboard** for visualizing traffic and alerts
- 🧾 Alert logging for later review

*(Update this list with anything specific to your rule set — e.g. exact ports/protocols monitored, or if there's export/reporting functionality.)*

---

## 🧱 Tech Stack

| Layer | Tool |
|---|---|
| Packet Capture | Scapy |
| Detection Logic | Python (rule-based) |
| Threat Mapping | MITRE ATT&CK |
| Dashboard | Streamlit |
| Language | Python 3.10+ |

---

## 📂 Project Structure

```
onyx-packet-sniffer/
├── sniffer/
│   ├── capture.py          # Scapy packet capture logic
│   ├── rules.py            # Detection rules / signatures
│   ├── mitre_mapping.py    # MITRE ATT&CK tagging
│   └── logger.py           # Alert logging
├── dashboard/
│   └── app.py              # Streamlit dashboard
├── assets/
│   └── dashboard-preview.png
├── requirements.txt
├── README.md
└── LICENSE
```

*(This is a suggested layout — reorganize your current files into this shape, or share your actual file list and I'll map it out precisely.)*

---

## ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/<your-username>/onyx-packet-sniffer.git
cd onyx-packet-sniffer

# Create a virtual environment
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

> ⚠️ Live packet capture requires elevated privileges. Run with `sudo` on macOS/Linux, or as Administrator on Windows.

---

## ▶️ Usage

```bash
# Start the packet sniffer (run with elevated privileges)
sudo python sniffer/capture.py

# In a separate terminal, launch the dashboard
streamlit run dashboard/app.py
```

*(Adjust these commands to match your actual entry points.)*

---

## 🗺️ MITRE ATT&CK Mapping

Detected events are mapped to relevant ATT&CK tactics/techniques to give each alert real-world context, e.g.:

| Detected Activity | ATT&CK Tactic | Technique |
|---|---|---|
| Port scanning behavior | Reconnaissance | T1595 |
| Traffic to known malicious IP | Command & Control | T1071 |

*(Fill in with your actual mapped tactics/techniques.)*

---

## 🎯 Why I Built This

I wanted hands-on practice with the full pipeline of network-based threat detection — not just reading about it, but building the capture, detection logic, and visualization myself. This project is part of my ongoing portfolio as I grow as a cybersecurity analyst focused on fraud investigation, OSINT, and threat detection.

---

## 🚧 Roadmap / Future Improvements

- [ ] Add anomaly-based detection alongside signature rules
- [ ] Nigeria/region-specific threat feed integration
- [ ] Export alerts to CSV/PDF reports
- [ ] Dockerize for easier deployment

---

## 👤 Author

**Onyeka Ojei**
Cybersecurity Analyst | OSINT & Fraud Investigation
[LinkedIn] · [Portfolio]

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
