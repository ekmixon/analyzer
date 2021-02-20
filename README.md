<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/analyzer/master/readme/analyzerlogo.png"></p>

#
[![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=Quality&query=$.grade&colorB=228B22&style=flat-square)](https://github.com/qeeqbox/analyzer/blob/master/info) [![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=version&query=$.version&colorB=blue&style=flat-square)](https://github.com/qeeqbox/analyzer/blob/master/changes.md) [![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=build&query=$.dockercomposebuild&colorB=green&style=flat-square)](https://github.com/qeeqbox/analyzer/blob/master/changes.md) [![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=test&query=$.automatedtest&colorB=green&style=flat-square)](https://github.com/qeeqbox/analyzer/blob/master/changes.md) [![Generic badge](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/qeeqbox/analyzer/master/info&label=implemented&query=$.implemented&colorB=lightgrey&style=flat-square)](https://github.com/qeeqbox/analyzer/blob/master/changes.md) [![Generic badge](https://img.shields.io/static/v1?label=%F0%9F%91%8D&message=!&color=yellow&style=flat-square)](https://github.com/qeeqbox/analyzer/stargazers)

This project automates the daily tasks of Threat Intelligence Analyzer role **internally** without external resources' interaction. It analyzes, visualizes and structures **sensitive** files or data by extracting features, artifacts and IoC using different modules. The output of those modules can be easily integrated in your research or SOC platforms.

## Install
```git clone https://github.com/qeeqbox/analyzer.git && cd analyzer &&  chmod +x run.sh && ./run.sh auto_configure```

## Interface
<img src="https://raw.githubusercontent.com/qeeqbox/analyzer/master/readme/intro.gif" style="max-width:768px"/>

## Output 
- [APT-Malware JSON\HTML reports (+190 sample)](https://files.qeeqbox.com/set1/)

## Features 
Runs locally (Offline) | Analyze buffer, file or full folder | Intime analysis (Session is saved)  | 2 modes (Interactive and silent) | Generates HTML or JSON as output | Dump output file with details to mongodb | Save raw json result to mongodb | Basic file information MD5, charset, mime, ssdeep | Different string/patterns analysis methods | NL English words detection | OCR words detection | IPS hints and countries description | Ports hints | World IPS world image and flags | DNS servers description (Top servers) | Websites similarity detection (Top 10000) | Artifacts force directed image | Cross references force directed image and table | MITRE att&ck tools and patterns detection (could be FP) | Similarity image divided to classes | YARA module and YARA rules included (Downloaded a copy from yara-rules-github) | YARA module includes conditions | Yara tags by index | URL/EMAIL/TEL/Tags patterns extraction | Credit Cards patterns extraction | Credential patterns extraction | Secrets patterns extraction | Encryption patterns (base64, md5, sha1..) extraction | DGA (Domain Generation Algorithm) patterns extraction | BOM (Byte Order Mark) detection | URL shorteners extraction | ASCII extraction from UNICODE | Whitelist implemented (Windows7, 8 and 10 files) | Check WAF and bypass proxy | Free/Fake email extraction | Spelling and punctuation check | Top phishing words included | Snort support | Web interface | (Linux wrapper) ELF information, API functions descriptions, System commands descriptions, Sections descriptions, Lib descriptions, Encrypted section detection, Symbols extraction, MITRE artifacts mapped to detection, Cross references detection, Behavior detection | (Windows wrapper) PE information, Encrypted section detection, Sections descriptions, DLL descriptions, Symbols extraction, Signature extraction and validation, API descriptions, PE ASLR, DEP, SEH and CFG detection, MITRE artifacts mapped to detection, API Behavior detection, DLL injection, Process Hollowing, Process Doppelganging etc.., Cross references detection, Icon extraction, Extract String file info, FileDescription, FileDescription etc.. | (Android wrapper) APK information, DEX information, Manifest descriptions, Intent descriptions, Resources extraction, Symbols extraction, Classes extraction, Big functions identification, Cross references detection, API Behavior detection | (IPhone built-in) IPA information | (BlackBerry COD built-in) COD information, Functions extraction, Strings extraction | (PCAP wrapper) Frame filter, HTTP filter, DNS filter, ARP filter, WAF detection, DGA detection, Snort parsing | (PDF built-in) Objects enumeration, Keys, javascript, js, OpenAction, extraction, Streams parsing, String analysis | (Office built-in and wrapper) Meta info extraction, Hyper and target links extraction, Bin printable parser, Extract Text, Extract DDE, Macros extraction | (OLE wrapper) Number of objects, Object extraction, Macros extraction | (EMAIL built-in and wrapper) Header information, Attachment extraction and parsing, Extract body, Phishing patterns check | (Archives wrapper) Extract mimes and guess by extensions, Finding patterns in all unpacked files, Encrypted archives detection | (HTML wrapper) Extract scripts, iframes, links and forms, Decode/analyze links, Script entropy | (Some patterns) AWS Clint ID, Amazon MWS Auth Token, Amazon S3, ALIYUN OSS, AZURE Storage, Facebook Access Token, Github Token, Goole API Key, Google CAPTCHA, Google OAuth, Google Secret, Google OAuth Access Token, Mailgun API Key, MailChimp API, Picatic API, Slack Token, Square Access Token, Square OAuth Secret, Stripe API, Twilio API, Twilio SID | Reduced file I/O | PDF module | RTF module | HTML module | Refactoring modules v2 | Converting some yara rules into individual modules (Requested by users) | Whitelist (Requested by users) | Switching to mongodb (Requested by users) | Phishing module | Web service and API | Web interface (Requested by users) | Curling some TIPs (Requested by users) | MS office module | Snort wrapper (Requested by users) | Adding more creds pattern (Requested by users)

## One click auto-configure
```bash
git clone https://github.com/qeeqbox/analyzer.git
cd analyzer
chmod +x run.sh
./run.sh auto_configure
The project interface http://127.0.0.1:8000/login/ will open automatically after finishing the initialization process
```

## Or, if you already have docker-compose
```bash
docker-compose -f docker-compose-dev.yml up --build
Then open http://127.0.0.1:8000/login/
```

## Prerequisites
apt-get install -y python3 python3-pip curl libfuzzy-dev yara libmagic-dev libjansson-dev libssl-dev libffi-dev tesseract-ocr libtesseract-dev libssl-dev swig p7zip-full radare2 dmg2img mongodb redis

pip3 install pyelftools macholib python-magic nltk Pillow jinja2 ssdeep pefile scapy r2pipe pytesseract M2Crypto requests tld tldextract bs4 psutil pymongo flask pyOpenSSL oletools extract_msg

Prerequisites packages are required for some modules (If you are having issues using those packages, I might be able to share with you my own alternatives that I developed in the past in C#\C)

## Roadmap
- Java analysis (Requested by users)
- Web detection
- Adding username and password wrappers to databases
- CSS clean up

## Resources
Linux documentation, MacOS documentation, Windows documentation, Android documentation, software77, MITRE ATT&CK™, sc0ty, hexacorn, PEID, steren, bacde, cisco umbrella , yara rules community , TONS OF RESEARCHES

## Other Licenses
By using this framework, you are accepting the license terms of all these packages: yara, Yara-Rules, tesseract-ocr, swig, radare, vu1tur, oletools, mongodb, supervisor, msg-extractor, snort, pyelftools, macholib, pefile, scapy, python-magic, flask, werkzeug, gunicorn, flask-mongoengine, flask-admin, flask-login, flask-bcrypt, pyopenssl, flask-markdown, tld, psutil, gevent, dateutil, requests, pymongo, BeautifulSoup, tldextract, m2crypto, radare2, ssdeep, jinja2, Pillow, nltk, p7zip, redislabs, redis-py

## Disclaimer\Notes
- Do not deploy without proper configuration
- Setup some security group rules and remove default credentials
- This project is NOT an anti malware project and does not quarantine or delete malicious files
- This project was developed for analyzing classified data and training some AI locally without internet/external interaction
- Please let me know if i missed a resource or dependency
