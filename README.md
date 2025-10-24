TITOLO: AI Security Scanner

# AI Security Scanner

![CI/CD](https://github.com/davidedellisanti90/ai-security-scanner-cyber-sentinel-group/workflows/CI%2FCD%20Pipeline/badge.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

![Coverage](https://img.shields.io/codecov/c/github/davidedellisanti90/ai-security-scanner-cyber-sentinel-group)
![Issues](https://img.shields.io/github/issues/davidedellisanti90/ai-security-scanner-cyber-sentinel-group)
![Stars](https://img.shields.io/github/stars/davidedellisanti90/ai-security-scanner-cyber-sentinel-group)

AI-powered security scanner using Nmap...

--------------------------------------------------------------
Team Cyber Sentinel

Il progetto AI Security Scanner è sviluppato da un gruppo di appassionati di cybersecurity e intelligenza artificiale che credono in un futuro in cui la sicurezza sia automatizzata, trasparente e accessibile a tutti.

Membri del team:

- Ivan Robert D’Arcangelo

- Davide Delli Santi

- Salvatore Scaramuzzi

- Rosita Lavarra

- Nicola Marella

- Lorenzo Misino

- Sonia Rendina

- Vinicius Tadeu Anselmo Leite

-----------------------------------------------------------------

AI Security Scanner è un progetto open-source che combina la potenza dell’intelligenza artificiale con strumenti di network scanning come Nmap, per rendere le analisi di sicurezza più intelligenti, leggibili e automatizzate.

🚀 Obiettivi del progetto

L’obiettivo è creare un sistema capace di:

Eseguire scansioni automatiche su reti e host.
Interpretare i risultati delle scansioni attraverso un parser intelligente.

Fornire report chiari e sintetici, supportati da modelli AI.

Automatizzare test e validazioni per garantire affidabilità e scalabilità.

🧩 Struttura del progetto\
ai-security-scanner/\
.
├── comandi_git.md\
├── examples\
│   ├── basic_scan.py\
│   └── complete_scan.py\

├── README.md
├── requirements.txt
├── src
│   ├── __init__.py
│   ├── parser
│   │   ├── __init__.py
│   │   ├── json_converter.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-312.pyc
│   │   │   ├── json_converter.cpython-312.pyc
│   │   │   └── xml_parser.cpython-312.pyc
│   │   └── xml_parser.py
│   ├── __pycache__
│   │   └── __init__.cpython-312.pyc
│   ├── scanner
│   │   ├── __init__.py
│   │   ├── nmap_wrapper.py
│   │   └── __pycache__
│   │       ├── __init__.cpython-312.pyc
│   │       └── nmap_wrapper.cpython-312.pyc
│   └── utils
│       └── __init__.py
├── tests
│   ├── __init__.py
│   ├── __pycache__
│   │   ├── __init__.cpython-312.pyc
│   │   ├── test_converter.cpython-312-pytest-7.4.4.pyc
│   │   ├── test_demo.cpython-312-pytest-7.4.4.pyc
│   │   ├── test_parser.cpython-312-pytest-7.4.4.pyc
│   │   └── test_scanner.cpython-312-pytest-7.4.4.pyc
│   ├── test_converter.py
│   ├── test_demo.py
│   ├── test_parser.py
│   └── test_scanner.py
├── test_scan.json
└── test_scan.xml

⚙️ Setup e dipendenze

Il progetto utilizza Python 3.x e strumenti di sicurezza come Nmap.
Assicurati di avere entrambi installati.

Installazione su Ubuntu
sudo apt update
sudo apt install nmap python3 python3-pip -y

Clona il progetto
git clone https://github.com/davidedellisanti90/ai-security-scanner-cyber-sentinel-group
cd ai-security-scanner

🧠 Come funziona

Lo script scanner.py avvia la scansione della rete.

I risultati vengono interpretati dal modulo parser/.

I dati elaborati vengono forniti in formato leggibile o pronti per essere analizzati da un modello AI.

Esempio d’uso:


python3 ai-security-scanner-cyber-sentinel-group/examples/complete_scan.py --target 192.168.1.0/24


📘 Documentazione

La documentazione completa e la bozza dell’architettura del progetto sono disponibili nella cartella /docs.
Qui vengono descritti:

Documenti

- 🔍 **Automated Network Scanning** - Nmap wrapper with Python
- 📊 **XML Parsing** - Extract structured data from scan results
- 🔄 **JSON Conversion** - AI-ready data format
- 📈 **Summary Generation** - Key metrics and statistics
- 🧪 **Comprehensive Testing** - 80%+ code coverage with pytest
- 🚀 **CI/CD Pipeline** - Automated testing with GitHub Actions
- 📚 **Professional Documentation** - Complete usage guides

Il flusso logico interno del sistema.

L’utente inserisce l’indirizzo IP da analizzare.

Il modulo scanner/nmap_wrapper.py lancia la scansione con Nmap.

I risultati XML vengono generati in scan_results/.

Il modulo parser/xml_parser.py legge il file XML.

Il modulo parser/json_converter.py converte i dati in JSON.

Il sistema mostra i risultati in output o li salva. 

Le integrazioni AI previste.

Le prossime fasi di sviluppo.

🔮 Prossimi sviluppi

Integrazione di modelli AI per l’analisi dei risultati.

Generazione automatica di report.

Dashboard web per visualizzare le scansioni in tempo reale.

Automazione dei test di sicurezza.

🤝 Contribuire

Le pull request sono benvenute!
Per idee, suggerimenti o collaborazioni, apri una issue o contatta il team.

🧾 Licenza

Distribuito sotto licenza MIT — libero di esplorare, modificare e migliorare.
