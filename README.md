# Awesome Hacking [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome Hacking. Inspired by [awesome-machine-learning](https://github.com/josephmisiti/awesome-machine-learning/)

If you want to contribute to this list (please do), send me a pull request or contact me [@carpedm20](https://twitter.com/carpedm20)

For a list of free hacking books available for download, go [here](https://github.com/Hack-with-Github/Free-Security-eBooks)


## Table of Contents

<!-- MarkdownTOC depth=4 -->

- [System](#system)
    - [Tutorials](#system-tutorials)
    - [Tools](#system-tools)
    - [Docker](#docker)
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
    - [Competition](#ctf-competiton)
    - [General](#ctf-general)
- [General](#general)

<!-- /MarkdownTOC -->

<a name="system" />
# System

<a name="system-tutorial" />
## Tutorials
 * [Corelan Team's Exploit writing tutorial](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
 * [Exploit Writing Tutorials for Pentesters](http://www.punter-infosec.com/exploit-writing-tutorials-for-pentesters/)

<a name="system-tools" />
## Tools
 * [Metasploit](https://github.com/rapid7/metasploit-framework) A computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.
 * [mimikatz](https://github.com/gentilkiwi/mimikatz) - A little tool to play with Windows security


<a name="system-general" />
## General
 * [Exploit database](https://www.exploit-db.com/) - An ultimate archive of exploits and vulnerable software


<a name="reverse-engineering" />
# Reverse Engineering

<a name="reverse-engineering-tutorial" />
## Tutorials
* [Lenas Reversing for Newbies](https://tuts4you.com/download.php?list.17)
* [Malware Analysis Tutorials: a Reverse Engineering Approach](http://fumalwareanalysis.blogspot.kr/p/malware-analysis-tutorials-reverse.html)

<a name="reverse-engineering-tools" />
## Tools
 * [IDA](https://www.hex-rays.com/products/ida/) - IDA is a Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger
 * [OllyDbg](http://www.ollydbg.de/) - A 32-bit assembler level analysing debugger for Windows
 * [dex2jar](https://github.com/pxb1988/dex2jar) - Tools to work with android .dex and java .class files
 * [JD-GUI](http://jd.benow.ca/) - A standalone graphical utility that displays Java source codes of “.class” files
 * [androguard](https://code.google.com/p/androguard/) - Reverse engineering, Malware and goodware analysis of Android applications
 * [JAD](http://varaneckas.com/jad/) - JAD Java Decompiler
 * [dotPeek](https://www.jetbrains.com/decompiler/) - a free-of-charge .NET decompiler from JetBrains
 * [UPX](http://upx.sourceforge.net/) - the Ultimate Packer for eXecutables
 * [radare2](https://github.com/radare/radare2) - A portable reversing framework
 * [plasma](https://github.com/joelpx/plasma) - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
 * [Hopper](https://www.hopperapp.com) - A OS X and Linux Disassembler/Decompiler for 32/64 bit Windows/Mac/Linux/iOS executables.

<a name="reverse-engineering-general" />
## General
 * [Open Malware](http://www.offensivecomputing.net/)


<a name="web" />
# Web

<a name="web-tools" />
## Tools
 * [sqlmap](https://github.com/sqlmapproject/sqlmap) - Automatic SQL injection and database takeover tool
 * [tools.web-max.ca](http://tools.web-max.ca/encode_decode.php) - base64 base85 md4,5 hash, sha1 hash encoding/decoding


<a name="network" />
# Network

<a name="network-tools" />
## Tools
 * [Wireshark](https://www.wireshark.org/) - A free and open-source packet analyzer
 * [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - A Network Forensic Analysis Tool (NFAT)
 * [tcpdump](http://www.tcpdump.org/) - a powerful command-line packet analyzer; and libpcap, a portable C/C++ library for network traffic capture
 * [Paros](http://sourceforge.net/projects/paros/) - A Java based HTTP/HTTPS proxy for assessing web application vulnerability
 * [pig](https://github.com/rafael-santiago/pig) - A Linux packet crafting tool
 * [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications
 * [mitmproxy](https://mitmproxy.org/) - An interactive, SSL-capable man-in-the-middle proxy for HTTP with a console interface
 * [mitmsocks4j](https://github.com/Akdeniz/mitmsocks4j) - Man in the Middle SOCKS Proxy for JAVA
 * [nmap](https://nmap.org/) - Nmap (Network Mapper) is a security scanner
 * [Aircrack-ng](http://www.aircrack-ng.org/) - An 802.11 WEP and WPA-PSK keys cracking program


<a name="forensic" />
# Forensic

<a name="forensic-tools" />
## Tools
 * [Autospy](http://www.sleuthkit.org/autopsy/) - A digital forensics platform and graphical interface to [The Sleuth Kit](http://www.sleuthkit.org/sleuthkit/index.php) and other digital forensics tools
 * [sleuthkit](https://github.com/sleuthkit/sleuthkit) - A library and collection of command line digital forensics tools
 * [EnCase](https://www.guidancesoftware.com/products/Pages/encase-forensic/overview.aspx) - the shared technology within a suite of digital investigations products by Guidance Software
 * [malzilla](http://malzilla.sourceforge.net/) - Malware hunting tool
 * [PEview](http://wjradburn.com/software/) - a quick and easy way to view the structure and content of 32-bit Portable Executable (PE) and Component Object File Format (COFF) files
 * [HxD](http://mh-nexus.de/en/hxd/) - A hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size
 * [WinHex](http://www.winhex.com/winhex/) - A hexadecimal editor, helpful in the realm of computer forensics, data recovery, low-level data processing, and IT security
 * [BinText](http://www.mcafee.com/kr/downloads/free-tools/bintext.aspx) - A small, very fast and powerful text extractor that will be of particular interest to programmers


# Cryptography

### Tools
 * [xortool](https://github.com/hellman/xortool) - A tool to analyze multi-byte xor cipher
 * [John the Ripper](http://www.openwall.com/john/) - A fast password cracker
 * [Aircrack](http://www.aircrack-ng.org/) - Aircrack is 802.11 WEP and WPA-PSK keys cracking program.

<a name="docker" />
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
 * `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)


<a name="wargame" />
# Wargame

<a name="wargame-system" />
## System
 * [OverTheWire - Semtex](http://overthewire.org/wargames/semtex/)
 * [OverTheWire - Vortex](http://overthewire.org/wargames/vortex/)
 * [OverTheWire - Drifter](http://overthewire.org/wargames/drifter/)
 * [pwnable.kr](http://pwnable.kr/) - Provide various pwn challenges regarding system security
 * [Exploit Exercises - Nebula](https://exploit-exercises.com/nebula/)
 * [SmashTheStack](http://smashthestack.org/)

<a name="wargame-reverse-engineering" />
## Reverse Engineering
 * [Reversing.kr](http://www.reversing.kr/) - This site tests your ability to Cracking & Reverse Code Engineering
 * [CodeEngn](http://codeengn.com/challenges/) - (Korean)
 * [simples.kr](http://simples.kr/) - (Korean)
 * [Crackmes.de](http://crackmes.de/) - The world first and largest community website for crackmes and reversemes.

<a name="wargame-web" />
## Web
 * [Hack This Site!](https://www.hackthissite.org/) - a free, safe and legal training ground for hackers to test and expand their hacking skills
 * [Webhacking.kr](http://webhacking.kr/)
 * [0xf.at](https://0xf.at/) - a website without logins or ads where you can solve password-riddles (so called hackits).


<a name="wargame-cryptography" />
## Cryptography
 * [OverTheWire - Krypton](http://overthewire.org/wargames/krypton/)


<a name="ctf" />
# CTF

<a name="ctf-competition" />
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

<a name="ctf-general" />
## General
 * [CTFtime.org](https://ctftime.org/) - All about CTF (Capture The Flag)
 * [WeChall](http://www.wechall.net/)
 * [CTF archives (shell-storm)](http://shell-storm.org/repo/CTF/)


<a name="etc" />
# ETC
 * [SecTools](http://sectools.org/) - Top 125 Network Security Tools
 * [Kali Linux](https://www.kali.org/) - Pen-Testing Linux Distribution
