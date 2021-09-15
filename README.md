# Awesome Hacking -An Amazing Project [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome Hacking. Inspired by [awesome-machine-learning](https://github.com/josephmisiti/awesome-machine-learning/)

If you want to contribute to this list (please do), send me a pull request or contact me [@carpedm20](https://twitter.com/carpedm20)

For a list of free hacking books available for download, go [here](https://github.com/Hack-with-Github/Free-Security-eBooks)


## Table of Contents

<!-- MarkdownTOC depth=4 -->

- [System](#system)
    - [Tutorials](#tutorials)
    - [Tools](#tools)
    - [Docker](#docker-images-for-penetration-testing--security)
    - [General](#general)
- [Reverse Engineering](#reverse-engineering)
    - [Tutorials](#tutorials-1)
    - [Tools](#tools-1)
    - [General](#general-1)
- [Web](#web)
    - [Tools](#tools-2)
    - [General](#general-2)
- [Network](#network)
    - [Tools](#tools-3)
- [Forensic](#forensic)
    - [Tools](#tools-4)
- [Cryptography](#cryptography)
    - [Tools](#tools-5)
- [Wargame](#wargame)
    - [System](#system-1)
    - [Reverse Engineering](#reverse-engineering-1)
    - [Web](#web-1)
    - [Cryptography](#cryptography-1)
    - [Bug bounty](#bug-bounty)
- [CTF](#ctf)
    - [Competition](#competition)
    - [General](#general-2)
- [OS](#os)
    - [Online resources](#online-resources)
- [Post exploitation](#post-exploitation)
    - [tools](#tools-6)
- [ETC](#etc)

<!-- /MarkdownTOC -->

# System

## Tutorials
 * [Roppers Computing Fundamentals](https://hoppersroppers.org/course.html)
    * Free, self-paced curriculum that builds a base of knowledge in computers and networking. Intended to build up a student with no prior technical knowledge to be confident in their ability to learn anything and continue their security education. Full text available as a [gitbook](https://www.hoppersroppers.org/fundamentals/).
 * [Corelan Team's Exploit writing tutorial](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
 * [Exploit Writing Tutorials for Pentesters](http://web.archive.org/web/20140916085343/http://www.punter-infosec.com/exploit-writing-tutorials-for-pentesters/)
 * [Understanding the basics of Linux Binary Exploitation](https://github.com/r0hi7/BinExp)
 * [Shells](https://www.youtube.com/playlist?list=PLyzOVJj3bHQuloKGG59rS43e29ro7I57J)
 * [Missing Semester](https://missing.csail.mit.edu/2020/course-shell/)


## Tools
 * [Metasploit](https://github.com/rapid7/metasploit-framework) A computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
 * [mimikatz](https://github.com/gentilkiwi/mimikatz) - A little tool to play with Windows security
 * [Hackers tools](https://www.youtube.com/playlist?list=PLyzOVJj3bHQuiujH1lpn8cA9dsyulbYRv) - Tutorial on tools.

### Docker Images for Penetration Testing & Security
 * `docker pull kalilinux/kali-linux-docker` [official Kali Linux](https://hub.docker.com/r/kalilinux/kali-linux-docker/)
 * `docker pull owasp/zap2docker-stable` - [official OWASP ZAP](https://github.com/zaproxy/zaproxy)
 * `docker pull wpscanteam/wpscan` - [official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
 * `docker pull metasploitframework/metasploit-framework
` - [Official Metasploit](https://hub.docker.com/r/metasploitframework/metasploit-framework/)
 * `docker pull citizenstig/dvwa` - [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/citizenstig/dvwa/)
 * `docker pull wpscanteam/vulnerablewordpress` - [Vulnerable WordPress Installation](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/)
 * `docker pull hmlio/vaas-cve-2014-6271` - [Vulnerability as a service: Shellshock](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/)
 * `docker pull hmlio/vaas-cve-2014-0160` - [Vulnerability as a service: Heartbleed](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)
 * `docker pull opendns/security-ninjas` - [Security Ninjas](https://hub.docker.com/r/opendns/security-ninjas/)
 * `docker pull noncetonic/archlinux-pentest-lxde` - [Arch Linux Penetration Tester](https://hub.docker.com/r/noncetonic/archlinux-pentest-lxde)
 * `docker pull diogomonica/docker-bench-security` - [Docker Bench for Security](https://hub.docker.com/r/diogomonica/docker-bench-security/)
 * `docker pull ismisepaul/securityshepherd` - [OWASP Security Shepherd](https://hub.docker.com/r/ismisepaul/securityshepherd/)
 * `docker pull danmx/docker-owasp-webgoat` - [OWASP WebGoat Project docker image](https://hub.docker.com/r/danmx/docker-owasp-webgoat/)
 * `docker pull vulnerables/web-owasp-nodegoat` - [OWASP NodeGoat](https://github.com/owasp/nodegoat#option-3---run-nodegoat-on-docker)
 * `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)
 * `docker pull bkimminich/juice-shop` - [OWASP Juice Shop](https://github.com/bkimminich/juice-shop#docker-container--)
 * `docker pull phocean/msf` - [Docker Metasploit](https://hub.docker.com/r/phocean/msf/)

## General
 * [Exploit database](https://www.exploit-db.com/) - An ultimate archive of exploits and vulnerable software


# Reverse Engineering

## Tutorials
* [Begin RE: A Reverse Engineering Tutorial Workshop](https://www.begin.re/the-workshop)
* [Malware Analysis Tutorials: a Reverse Engineering Approach](http://fumalwareanalysis.blogspot.kr/p/malware-analysis-tutorials-reverse.html)
* [Malware Unicorn Reverse Engineering Tutorial](https://malwareunicorn.org/workshops/re101.html#0)
* [Lena151: Reversing With Lena](https://archive.org/details/lena151)

## Tools
### Disassemblers and debuggers
 * [IDA](https://www.hex-rays.com/products/ida/) - IDA is a Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger
 * [OllyDbg](http://www.ollydbg.de/) - A 32-bit assembler level analysing debugger for Windows
 * [x64dbg](https://github.com/x64dbg/x64dbg) - An open-source x64/x32 debugger for Windows
 * [radare2](https://github.com/radare/radare2) - A portable reversing framework
 * [plasma](https://github.com/joelpx/plasma) - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
 * [ScratchABit](https://github.com/pfalcon/ScratchABit) - Easily retargetable and hackable interactive disassembler with IDAPython-compatible plugin API
 * [Capstone](https://github.com/aquynh/capstone)
 * [Ghidra](https://ghidra-sre.org/) - A software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate in support of the Cybersecurity mission

### Decompilers
*  JVM-based languages
  * [Krakatau](https://github.com/Storyyeller/Krakatau) - the best decompiler I have used. Is able to decompile apps written in Scala and Kotlin into Java code. JD-GUI and Luyten have failed to do it fully.
  * [JD-GUI](https://github.com/java-decompiler/jd-gui)
  * [procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler)
    * [Luyten](https://github.com/deathmarine/Luyten) - one of the best, though a bit slow, hangs on some binaries and not very well maintained.
  * [JAD](http://varaneckas.com/jad/) - JAD Java Decompiler (closed-source, unmaintained)
  * [JADX](https://github.com/skylot/jadx) - a decompiler for Android apps. Not related to JAD.

* .net-based languages
  * [dotPeek](https://www.jetbrains.com/decompiler/) - a free-of-charge .NET decompiler from JetBrains
  * [ILSpy](https://github.com/icsharpcode/ILSpy/) - an open-source .NET assembly browser and decompiler
  * [dnSpy](https://github.com/0xd4d/dnSpy) - .NET assembly editor, decompiler, and debugger

* native code
  * [Hopper](https://www.hopperapp.com) - A OS X and Linux Disassembler/Decompiler for 32/64-bit Windows/Mac/Linux/iOS executables.
  * [cutter](https://github.com/radareorg/cutter) - a decompiler based on radare2.
  * [retdec](https://github.com/avast-tl/retdec)
  * [snowman](https://github.com/yegord/snowman)
  * [Hex-Rays](https://www.hex-rays.com/products/decompiler/)

* Python
  * [uncompyle6](https://github.com/rocky/python-uncompyle6) - decompiler for the over 20 releases and 20 years of CPython.


### Deobfuscators
 * [de4dot](https://github.com/0xd4d/de4dot) - .NET deobfuscator and unpacker.
 * [JS Beautifier](https://github.com/beautify-web/js-beautify)
 * [JS Nice](http://jsnice.org/) - a web service guessing JS variables names and types based on the model derived from open source.

### Other
 * [nudge4j](https://github.com/lorenzoongithub/nudge4j) - Java tool to let the browser talk to the JVM
 * [dex2jar](https://github.com/pxb1988/dex2jar) - Tools to work with Android .dex and Java .class files
 * [androguard](https://code.google.com/p/androguard/) - Reverse engineering, malware and goodware analysis of Android applications
 * [antinet](https://github.com/0xd4d/antinet) - .NET anti-managed debugger and anti-profiler code
 * [UPX](http://upx.sourceforge.net/) - the Ultimate Packer (and unpacker) for eXecutables

### Execution logging and tracing
 * [Wireshark](https://www.wireshark.org/) - A free and open-source packet analyzer
 * [tcpdump](http://www.tcpdump.org/) - A powerful command-line packet analyzer; and libpcap, a portable C/C++ library for network traffic capture
 * [mitmproxy](https://github.com/mitmproxy/mitmproxy) - An interactive, SSL-capable man-in-the-middle proxy for HTTP with a console interface
 * [Charles Proxy](https://charlesproxy.com) - A cross-platform GUI web debugging proxy to view intercepted HTTP and HTTPS/SSL live traffic
 * [usbmon](https://www.kernel.org/doc/Documentation/usb/usbmon.txt) - USB capture for Linux.
 * [USBPcap](https://github.com/desowin/usbpcap) - USB capture for Windows.
 * [dynStruct](https://github.com/ampotos/dynStruct) - structures recovery via dynamic instrumentation.
 * [drltrace](https://github.com/mxmssh/drltrace) - shared library calls tracing.

### Binary files examination and editing

#### Hex editors
 * [HxD](http://mh-nexus.de/en/hxd/) - A hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size
 * [WinHex](http://www.winhex.com/winhex/) - A hexadecimal editor, helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security
* [wxHexEditor](https://github.com/EUA/wxHexEditor)
* [Synalize It](https://www.synalysis.net/)/[Hexinator](https://hexinator.com/) -

#### Other
 * [Binwalk](https://github.com/ReFirmLabs/binwalk) -  Detects signatures, unpacks archives, visualizes entropy.
 * [Veles](https://github.com/codilime/veles) - a visualizer for statistical properties of blobs.
 * [Kaitai Struct](https://github.com/kaitai-io/kaitai_struct) - a DSL for creating parsers in a variety of programming languages. The Web IDE is particularly useful for reverse-engineering.
 * [Protobuf inspector](https://github.com/jmendeth/protobuf-inspector)
 * [DarunGrim](https://github.com/ohjeongwook/DarunGrim) - executable differ.
 * [DBeaver](https://github.com/dbeaver/dbeaver) - a DB editor.
 * [Dependencies](https://github.com/lucasg/Dependencies) - a FOSS replacement to Dependency Walker.
 * [PEview](http://wjradburn.com/software/) - A quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files
* [BinText](https://web.archive.org/web/http://www.mcafee.com/kr/downloads/free-tools/bintext.aspx) - A small, very fast and powerful text extractor that will be of particular interest to programmers.

## General
 * [Open Malware](http://www.offensivecomputing.net/)

# Web

## Tools
 * [Spyse](https://spyse.com/) -  Data gathering service that collects web info using OSINT. Provided info: IPv4 hosts, domains/whois, ports/banners/protocols, technologies, OS, AS, maintains huge SSL/TLS DB, and more... All the data is stored in its own database allowing get the data without scanning.
 * [sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool
 * [NoSQLMap](https://github.com/codingo/NoSQLMap) - Automated NoSQL database enumeration and web application exploitation tool.
 * [tools.web-max.ca](http://tools.web-max.ca/encode_decode.php) - base64 base85 md4,5 hash, sha1 hash encoding/decoding
 * [VHostScan](https://github.com/codingo/VHostScan) - A virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, aliases and dynamic default pages.
 * [SubFinder](https://github.com/subfinder/subfinder) - SubFinder is a subdomain discovery tool that discovers valid subdomains for any target using passive online sources.
 * [Findsubdomains](https://findsubdomains.com/) - A subdomains discovery tool that collects all possible subdomains from open source internet and validates them through various tools to provide accurate results.
 * [badtouch](https://github.com/kpcyrd/badtouch) - Scriptable network authentication cracker
 * [PhpSploit](https://github.com/nil0x42/phpsploit) - Full-featured C2 framework which silently persists on webserver via evil PHP oneliner
 * [Git-Scanner](https://github.com/HightechSec/git-scanner) - A tool for bug hunting or pentesting for targeting websites that have open `.git` repositories available in public
 * [CSP Scanner](https://cspscanner.com/) - Analyze a site's Content-Security-Policy (CSP) to find bypasses and missing directives.

## General
 * [Strong node.js](https://github.com/jesusprubio/strong-node) - An exhaustive checklist to assist in the source code security analysis of a node.js web service.


# Network

## Tools
 * [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - A Network Forensic Analysis Tool (NFAT)
 * [Paros](http://sourceforge.net/projects/paros/) - A Java-based HTTP/HTTPS proxy for assessing web application vulnerability
 * [pig](https://github.com/rafael-santiago/pig) - A Linux packet crafting tool
 * [findsubdomains](https://findsubdomains.com) - really fast subdomains scanning service that has much greater opportunities than simple subs finder(works using OSINT).
 * [cirt-fuzzer](http://www.cirt.dk/) - A simple TCP/UDP protocol fuzzer.
 * [ASlookup](https://aslookup.com/) - a useful tool for exploring autonomous systems and all related info (CIDR, ASN, Org...)
 * [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications
 * [mitmsocks4j](https://github.com/Akdeniz/mitmsocks4j) - Man-in-the-middle SOCKS Proxy for Java
 * [ssh-mitm](https://github.com/jtesta/ssh-mitm) - An SSH/SFTP man-in-the-middle tool that logs interactive sessions and passwords.
 * [nmap](https://nmap.org/) - Nmap (Network Mapper) is a security scanner
 * [Aircrack-ng](http://www.aircrack-ng.org/) - An 802.11 WEP and WPA-PSK keys cracking program
 * [Nipe](https://github.com/GouveaHeitor/nipe) - A script to make Tor Network your default gateway.
 * [Habu](https://github.com/portantier/habu) - Python Network Hacking Toolkit
 * [Wifi Jammer](https://n0where.net/wifijammer/) - Free program to jam all wifi clients in range
 * [Firesheep](https://codebutler.github.io/firesheep/) - Free program for HTTP session hijacking attacks.
 * [Scapy](https://github.com/secdev/awesome-scapy) - A Python tool and library for low level packet creation and manipulation
 * [Amass](https://github.com/OWASP/Amass) - In-depth subdomain enumeration tool that performs scraping, recursive brute forcing, crawling of web archives, name altering and reverse DNS sweeping
 * [sniffglue](https://github.com/kpcyrd/sniffglue) - Secure multithreaded packet sniffer
 * [Netz](https://github.com/spectralops/netz) - Discover internet-wide misconfigurations, using zgrab2 and others.
 * [RustScan](https://github.com/rustscan/rustscan) - Extremely fast port scanner built with Rust, designed to scan all ports in a couple of seconds and utilizes nmap to perform port enumeration in a fraction of the time.

# Forensic

## Tools
 * [Autopsy](http://www.sleuthkit.org/autopsy/) - A digital forensics platform and graphical interface to [The Sleuth Kit](http://www.sleuthkit.org/sleuthkit/index.php) and other digital forensics tools
 * [sleuthkit](https://github.com/sleuthkit/sleuthkit) - A library and collection of command-line digital forensics tools
 * [EnCase](https://www.guidancesoftware.com/products/Pages/encase-forensic/overview.aspx) - The shared technology within a suite of digital investigations products by Guidance Software
 * [malzilla](http://malzilla.sourceforge.net/) - Malware hunting tool
 * [IPED - Indexador e Processador de Evidências Digitais](https://servicos.dpf.gov.br/ferramentas/IPED/) - Brazilian Federal Police Tool for Forensic Investigation

# Cryptography

### Tools
 * [xortool](https://github.com/hellman/xortool) - A tool to analyze multi-byte XOR cipher
 * [John the Ripper](http://www.openwall.com/john/) - A fast password cracker
 * [Aircrack](http://www.aircrack-ng.org/) - Aircrack is 802.11 WEP and WPA-PSK keys cracking program.
 * [Ciphey](https://github.com/ciphey/ciphey) - Automated decryption tool using artificial intelligence & natural language processing.


# Wargame

## System
 * [OverTheWire - Semtex](http://overthewire.org/wargames/semtex/)
 * [OverTheWire - Vortex](http://overthewire.org/wargames/vortex/)
 * [OverTheWire - Drifter](http://overthewire.org/wargames/drifter/)
 * [pwnable.kr](http://pwnable.kr/) - Provide various pwn challenges regarding system security
 * [Exploit Exercises - Nebula](https://exploit-exercises.com/nebula/)
 * [SmashTheStack](http://smashthestack.org/)
 * [HackingLab](https://www.hacking-lab.com/) 

## Reverse Engineering
 * [Reversing.kr](http://www.reversing.kr/) - This site tests your ability to Cracking & Reverse Code Engineering
 * [CodeEngn](http://codeengn.com/challenges/) - (Korean)
 * [simples.kr](http://simples.kr/) - (Korean)
 * [Crackmes.de](http://crackmes.de/) - The world first and largest community website for crackmes and reversemes.

## Web
 * [Hack This Site!](https://www.hackthissite.org/) - a free, safe and legal training ground for hackers to test and expand their hacking skills
 * [Hack The Box](https://www.hackthebox.eu) - a free site to perform pentesting in a variety of different systems.
 * [Webhacking.kr](http://webhacking.kr/)
 * [0xf.at](https://0xf.at/) - a website without logins or ads where you can solve password-riddles (so called hackits).
 * [fuzzy.land](https://fuzzy.land/) - Website by an Austrian group. Lots of challenges taken from CTFs they participated in.
 * [Gruyere](https://google-gruyere.appspot.com/)
 * [Others](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project#tab=On-Line_apps)

## Cryptography
 * [OverTheWire - Krypton](http://overthewire.org/wargames/krypton/)

## Bug bounty
  * [Awesome bug bounty resources by EdOverflow](https://github.com/EdOverflow/bugbounty-cheatsheet)

## Bug bounty -  Earn Some Money
  * [Bugcrowd](https://www.bugcrowd.com/)
  * [Hackerone](https://www.hackerone.com/start-hacking)


# CTF

## Competition
 * [DEF CON](https://legitbs.net/)
 * [CSAW CTF](https://ctf.isis.poly.edu/)
 * [hack.lu CTF](http://hack.lu/)
 * [Pliad CTF](http://www.plaidctf.com/)
 * [RuCTFe](http://ructf.org/e/)
 * [Ghost in the Shellcode](http://ghostintheshellcode.com/)
 * [PHD CTF](http://www.phdays.com/)
 * [SECUINSIDE CTF](http://secuinside.com/)
 * [Codegate CTF](http://ctf.codegate.org/html/Main.html?lang=eng)
 * [Boston Key Party CTF](http://bostonkeyparty.net/)
 * [ZeroDays CTF](https://zerodays.ie/)
 * [Insomni’hack](https://insomnihack.ch/)
 * [Pico CTF](https://picoctf.com/)
 * [prompt(1) to win](http://prompt.ml/) - XSS Challenges
 * [HackTheBox](https://www.hackthebox.eu/)

## General
 * [Hack+](http://hack.plus) - An Intelligent network of bots that fetch the latest InfoSec content.
 * [CTFtime.org](https://ctftime.org/) - All about CTF (Capture The Flag)
 * [WeChall](http://www.wechall.net/)
 * [CTF archives (shell-storm)](http://shell-storm.org/repo/CTF/)
 * [Rookit Arsenal](https://amzn.com/144962636X) - OS RE and rootkit development
 * [Pentest Cheat Sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets) - Collection of cheat sheets useful for pentesting
 * [Movies For Hackers](https://github.com/k4m4/movies-for-hackers) - A curated list of movies every hacker & cyberpunk must watch.
 * [Roppers CTF Fundamentals Course](https://www.hoppersroppers.org/courseCTF.html) - Free course designed to get a student crushing CTFs as quickly as possible. Teaches the mentality and skills required for crypto, forensics, and more. Full text available as a [gitbook](https://www.hoppersroppers.org/ctf/).

# OS

## Online resources
 * [Security related Operating Systems @ Rawsec](http://rawsec.ml/en/security-related-os/) - Complete list of security related operating systems
 * [Best Linux Penetration Testing Distributions @ CyberPunk](https://n0where.net/best-linux-penetration-testing-distributions/) - Description of main penetration testing distributions
 * [Security @ Distrowatch](http://distrowatch.com/search.php?category=Security) - Website dedicated to talking about, reviewing and keeping up to date with open source operating systems
# Post exploitation

## tools
* [empire](https://github.com/EmpireProject/Empire) - A post exploitation framework for powershell and python.
* [silenttrinity](https://github.com/byt3bl33d3r/SILENTTRINITY) - A post exploitation tool that uses iron python to get past powershell restrictions.
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - A PowerShell post exploitation framework
* [ebowla](https://github.com/Genetic-Malware/Ebowla) - Framework for Making Environmental Keyed Payloads

# ETC
 * [SecTools](http://sectools.org/) - Top 125 Network Security Tools
 * [Roppers Security Fundamentals](https://www.hoppersroppers.org/courseSecurity.html) - Free course that teaches a beginner how security works in the real world. Learn security theory and execute defensive measures so that you are better prepared against threats online and in the physical world. Full text available as a [gitbook](https://www.hoppersroppers.org/security/).
