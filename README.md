# Awesome Hacking [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome Hacking. Inspired by [awesome-machine-learning](https://github.com/josephmisiti/awesome-machine-learning/)

If you want to contribute to this list (please do), send me a pull request or contact me [@carpedm20](https://twitter.com/carpedm20)

For a list of free hacking books available for download, go [here](https://github.com/Hack-with-Github/Free-Security-eBooks)


## Table of Contents

<!-- MarkdownTOC depth=4 -->

- [System](#system)
    - [Tutorials](#system-tutorials)
    - [Tools](#system-tools)
    - [Docker](#system-docker)
    - [General](#system-general)
- [Reverse Engineering](#reverse-engineering)
    - [Tutorials](#reverse-engineering-tutorials)
    - [Tools](#reverse-engineering-tools)
    - [General](#reverse-engineering-general)
- [Web](#web)
    - [Tutorials](#web-tutorials)
    - [Tools](#web-tools)
- [Network](#network)
    - [Tutorials](#network-tutorials)
    - [Tools](#network-tools)
- [BugBounty](#bugbounty)
- [Forensic](#forensic)
    - [Tutorials](#forensic-tutorials)
    - [Tools](#forensic-tools)
- [Cryptography](#cryptography)
    - [Tutorials](#cryptography-tutorials)
    - [Tools](#cryptography-tools)
- [Wargame](#wargame)
    - [System](#wargame-system)
    - [Reverse Engineering](#wargame-reverse-engineering)
    - [Web](#wargame-web)
    - [Network](#wargame-network)
    - [Forensic](#wargame-forensic)
    - [Cryptography](#wargame-cryptography)
- [CTF](#ctf)
    - [Competition](#ctf-competition)
    - [General](#ctf-general)
- [OS](#os)
    - [Online resources](#online-resources)
- [ETC](#etc)

<!-- /MarkdownTOC -->

# System

## Tutorials
 * [Corelan Team's Exploit writing tutorial](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
 * [Exploit Writing Tutorials for Pentesters](http://www.punter-infosec.com/exploit-writing-tutorials-for-pentesters/)

## Tools
 * [Metasploit](https://github.com/rapid7/metasploit-framework) A computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
 * [mimikatz](https://github.com/gentilkiwi/mimikatz) - A little tool to play with Windows security

### Docker Images for Penetration Testing & Security
 * `docker pull kalilinux/kali-linux-docker` [official Kali Linux](https://hub.docker.com/r/kalilinux/kali-linux-docker/)
 * `docker pull owasp/zap2docker-stable` - [official OWASP ZAP](https://github.com/zaproxy/zaproxy)
 * `docker pull wpscanteam/wpscan` - [official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
 * `docker pull pandrew/metasploit` - [docker-metasploit](https://hub.docker.com/r/pandrew/metasploit/)
 * `docker pull citizenstig/dvwa` - [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/citizenstig/dvwa/)
 * `docker pull wpscanteam/vulnerablewordpress` - [Vulnerable WordPress Installation](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/)
 * `docker pull hmlio/vaas-cve-2014-6271` - [Vulnerability as a service: Shellshock](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/)
 * `docker pull hmlio/vaas-cve-2014-0160` - [Vulnerability as a service: Heartbleed](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)
 * `docker pull opendns/security-ninjas` - [Security Ninjas](https://hub.docker.com/r/opendns/security-ninjas/)
 * `docker pull usertaken/archlinux-pentest-lxde` - [Arch Linux Penetration Tester](https://hub.docker.com/r/usertaken/archlinux-pentest-lxde/)
 * `docker pull diogomonica/docker-bench-security` - [Docker Bench for Security](https://hub.docker.com/r/diogomonica/docker-bench-security/)
 * `docker pull ismisepaul/securityshepherd` - [OWASP Security Shepherd](https://hub.docker.com/r/ismisepaul/securityshepherd/)
 * `docker pull danmx/docker-owasp-webgoat` - [OWASP WebGoat Project docker image](https://hub.docker.com/r/danmx/docker-owasp-webgoat/)
 * `docker-compose build && docker-compose up` - [OWASP NodeGoat](https://github.com/owasp/nodegoat#option-3---run-nodegoat-on-docker)
 * `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)
 * `docker pull bkimminich/juice-shop` - [OWASP Juice Shop](https://github.com/bkimminich/juice-shop#docker-container--)

## General
 * [Exploit database](https://www.exploit-db.com/) - An ultimate archive of exploits and vulnerable software


# Reverse Engineering

## Tutorials
* [Lenas Reversing for Newbies](https://tuts4you.com/download.php?list.17)
* [Malware Analysis Tutorials: a Reverse Engineering Approach](http://fumalwareanalysis.blogspot.kr/p/malware-analysis-tutorials-reverse.html)

## Tools
 * [nudge4j](https://github.com/lorenzoongithub/nudge4j) - Java tool to let the browser talk to the JVM
 * [IDA](https://www.hex-rays.com/products/ida/) - IDA is a Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger
 * [OllyDbg](http://www.ollydbg.de/) - A 32-bit assembler level analysing debugger for Windows
 * [x64dbg](http://x64dbg.com/) - An open-source x64/x32 debugger for Windows
 * [dex2jar](https://github.com/pxb1988/dex2jar) - Tools to work with Android .dex and Java .class files
 * [JD-GUI](http://jd.benow.ca/) - A standalone graphical utility that displays Java source codes of “.class” files
 * [procyon](https://bitbucket.org/mstrobel/procyon/wiki/Java%20Decompiler) - A modern open-source Java decompiler
 * [androguard](https://code.google.com/p/androguard/) - Reverse engineering, malware and goodware analysis of Android applications
 * [JAD](http://varaneckas.com/jad/) - JAD Java Decompiler (closed-source, unmaintained)
 * [dotPeek](https://www.jetbrains.com/decompiler/) - a free-of-charge .NET decompiler from JetBrains
 * [ILSpy](https://github.com/icsharpcode/ILSpy/) - an open-source .NET assembly browser and decompiler
 * [dnSpy](https://github.com/0xd4d/dnSpy) - .NET assembly editor, decompiler, and debugger 
 * [de4dot](https://github.com/0xd4d/de4dot) - .NET deobfuscator and unpacker. 
 * [antinet](https://github.com/0xd4d/antinet) - .NET anti-managed debugger and anti-profiler code 
 * [UPX](http://upx.sourceforge.net/) - the Ultimate Packer for eXecutables
 * [radare2](https://github.com/radare/radare2) - A portable reversing framework
 * [plasma](https://github.com/joelpx/plasma) - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
 * [Hopper](https://www.hopperapp.com) - A OS X and Linux Disassembler/Decompiler for 32/64-bit Windows/Mac/Linux/iOS executables.
 * [ScratchABit](https://github.com/pfalcon/ScratchABit) - Easily retargetable and hackable interactive disassembler with IDAPython-compatible plugin API



## General
 * [Open Malware](http://www.offensivecomputing.net/)


# Web

## Tools
 * [sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool
 * [tools.web-max.ca](http://tools.web-max.ca/encode_decode.php) - base64 base85 md4,5 hash, sha1 hash encoding/decoding


# Network

## Tools
 * [Wireshark](https://www.wireshark.org/) - A free and open-source packet analyzer
 * [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - A Network Forensic Analysis Tool (NFAT)
 * [tcpdump](http://www.tcpdump.org/) - A powerful command-line packet analyzer; and libpcap, a portable C/C++ library for network traffic capture
 * [Paros](http://sourceforge.net/projects/paros/) - A Java-based HTTP/HTTPS proxy for assessing web application vulnerability
 * [pig](https://github.com/rafael-santiago/pig) - A Linux packet crafting tool
 * [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications
 * [mitmproxy](https://mitmproxy.org/) - An interactive, SSL-capable man-in-the-middle proxy for HTTP with a console interface
 * [mitmsocks4j](https://github.com/Akdeniz/mitmsocks4j) - Man-in-the-middle SOCKS Proxy for Java
 * [nmap](https://nmap.org/) - Nmap (Network Mapper) is a security scanner
 * [Aircrack-ng](http://www.aircrack-ng.org/) - An 802.11 WEP and WPA-PSK keys cracking program
 * [Charles Proxy](https://charlesproxy.com) - A cross-platform GUI web debugging proxy to view intercepted HTTP and HTTPS/SSL live traffic
 * [Nipe](https://github.com/GouveaHeitor/nipe) - A script to make Tor Network your default gateway. 
 * [Habu](https://github.com/portantier/habu) - Python Network Hacking Toolkit
 * [Wifi Jammer](https://n0where.net/wifijammer/) - Free program to jam all wifi clients in range
 * [Firesheep](https://codebutler.github.io/firesheep/) - Free program for HTTP session hijacking attacks.
 * [Scapy](https://github.com/secdev/scapy) - A Python tool and library for low level packet creation and maniputalion


# Forensic

## Tools
 * [Autopsy](http://www.sleuthkit.org/autopsy/) - A digital forensics platform and graphical interface to [The Sleuth Kit](http://www.sleuthkit.org/sleuthkit/index.php) and other digital forensics tools
 * [sleuthkit](https://github.com/sleuthkit/sleuthkit) - A library and collection of command-line digital forensics tools
 * [EnCase](https://www.guidancesoftware.com/products/Pages/encase-forensic/overview.aspx) - The shared technology within a suite of digital investigations products by Guidance Software
 * [malzilla](http://malzilla.sourceforge.net/) - Malware hunting tool
 * [PEview](http://wjradburn.com/software/) - A quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files
 * [HxD](http://mh-nexus.de/en/hxd/) - A hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size
 * [WinHex](http://www.winhex.com/winhex/) - A hexadecimal editor, helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security
 * [BinText](http://www.mcafee.com/kr/downloads/free-tools/bintext.aspx) - A small, very fast and powerful text extractor that will be of particular interest to programmers


# Cryptography

### Tools
 * [xortool](https://github.com/hellman/xortool) - A tool to analyze multi-byte XOR cipher
 * [John the Ripper](http://www.openwall.com/john/) - A fast password cracker
 * [Aircrack](http://www.aircrack-ng.org/) - Aircrack is 802.11 WEP and WPA-PSK keys cracking program.


# Wargame

## System
 * [OverTheWire - Semtex](http://overthewire.org/wargames/semtex/)
 * [OverTheWire - Vortex](http://overthewire.org/wargames/vortex/)
 * [OverTheWire - Drifter](http://overthewire.org/wargames/drifter/)
 * [pwnable.kr](http://pwnable.kr/) - Provide various pwn challenges regarding system security
 * [Exploit Exercises - Nebula](https://exploit-exercises.com/nebula/)
 * [SmashTheStack](http://smashthestack.org/)

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


## Cryptography
 * [OverTheWire - Krypton](http://overthewire.org/wargames/krypton/)

## Bug bounty
  * [Awesome bug bounty resources by EdOverflow](https://github.com/EdOverflow/bugbounty-cheatsheet)

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

## General
 * [Hack+](http://hack.plus) - An Intelligent network of bots that fetch the latest InfoSec content.
 * [CTFtime.org](https://ctftime.org/) - All about CTF (Capture The Flag)
 * [WeChall](http://www.wechall.net/)
 * [CTF archives (shell-storm)](http://shell-storm.org/repo/CTF/)
 * [Rookit Arsenal](https://amzn.com/144962636X) - OS RE and rootkit development
 * [Pentest Cheat Sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets) - Collection of cheat sheets useful for pentesting
 * [Movies For Hackers](https://github.com/k4m4/movies-for-hackers) - A curated list of movies every hacker & cyberpunk must watch.

# OS

## Online resources
 * [Security related Operating Systems @ Rawsec](http://rawsec.ml/en/security-related-os/) - Complete list of security related operating systems
 * [Best Linux Penetration Testing Distributions @ CyberPunk](https://n0where.net/best-linux-penetration-testing-distributions/) - Description of main penetration testing distributions
 * [Security @ Distrowatch](http://distrowatch.com/search.php?category=Security) - Website dedicated to talking about, reviewing and keeping up to date with open source operating systems

# ETC
 * [SecTools](http://sectools.org/) - Top 125 Network Security Tools
