Exercícios: https://github.com/devairdarolt/OSRC---Network-Security/tree/master/trunk/labs


# OSRC---Network-Security
Aulas de Segurança de Redes com professor rafael obelheiro
https://nps.edu/web/c3o/labtainers

Labtainers include more than 50 cyber lab exercises and tools to build your own. Import a single VM appliance or install on a Linux system and your students are done with provisioning and administrative setup, for these and future lab exercises (brief demo).

Consistent lab execution environments and automated provisioning via Docker containers
Multi-component network topologies on a modestly performing laptop computer (50 second Demo)
Automated assessment of student lab activity and progress
Individualized lab exercises to discourage sharing solutions
Labtainers provide controlled and consistent execution environments in which students perform labs entirely within the confines of their computer, regardless of the Linux distribution and packages installed on the student's computer or VM.  The only requirement is that the Linux system supports Docker.  See Labtainers Papers below for additional information about the framework.

Labtainers includes over 50 lab exercises summarized here.   The framework is free and open, making it easy for educators to create and share their own Labtainer exercises.  Please refer to the Lab Designer User Guide for details on using the framework to create and adapt lab exercises.  Labtainers code and data is managed on GitHub.  Consider contributing your new labs via GitHub pull requests.

1. VM para Virtual Box:     https://nps.edu/web/c3o/virtual-machine-images
2. Guia do estudante:       https://github.com/mfthomps/Labtainers/raw/master/docs/student/labtainer-student.pdf
3. Manual dos laboratórios  https://github.com/mfthomps/Labtainers/releases/latest/download/labtainer_pdf.zip


Conteúdo de laboratórios disponíveis na VM

Com a VM aberta rodar o seguinte comando:
1 $  labtainer <lab>    // labtainer bufoverflow
2 

|              | Software Vulnerabilities                                                                         |            |
|--------------|--------------------------------------------------------------------------------------------------|------------|
| Lab          | Description                                                                                      | difficulty |
| bufoverflow  | An example program vulnerable to a stack buffer overflow, derived from a SEED lab.               |      3     |
| buf64        | A 64-bit version of the bufoverflow lab                                                          |      3     |
| formatstring | Explore C library printf function vulnerabilities, derived from a SEED lab.                      |      2     |
| format64     | A 64-bit version of the formatstring lab                                                         |      2     |
| retlibc      |  Exploit a program using a buffer overflow and return-to-libc, derived from a SEED lab.          |      3     |
| gdblesson    | An introduction to using gdb to debug a simple C program.                                        |      1     |
| metasploit   | Use metasploit on a Kali Linux system to attack a "metasploitable" host.                         |      1     |
| setuid-env   | Risks of the setuid feature, including environment variables, derived from a SEED lab.           |      2     |
| ghidra       | Reverse engineer a simple vulnerable service to discover and demonstrate some of its properties. |      2     |
| cgc          | Explore over 200 vulnerable services from the DARPA Cyber Grand Challenge.                       |      3     |




|                                                                                          | Networking                                                                                                                                                                 |            |
|------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| Lab                                                                                      | Description                                                                                                                                                                | difficulty |
| telnetlab                                                                                | The student uses telnet to access a remote computer, and employs the tcpdump tool to view plaintext passwords, and to observe how use of ssh mitigates that vulnerability. |      1     |
| nmap-discovery                                                                           | The nmap utility is used to locate an ssh server on a network and to discover the port number being used by the service.                                                   |      2     |
| nmap-ssh                                                                                 | The nmap utility is utilized in combination with the tshark network traffic analysis utility to demonstrate a security problem with an ssh server.                         |      2     |
| routing-basics                                                                           | A simple routing example with two LANs and an internet connection via NAT                                                                                                  |      2     |
| iptables                                                                                 | The iptables utility is used to configure a “firewall” component to only forward selected application service traffic between a client and a server.                       |      2     |
| tcpip                                                                                    | TCP/IP protocol vulnerabilities, including SYN flooding, RST attacks and session hijacking.  Derived from the SEED lab.                                                    |      2     |
| arp-spoof                                                                                | Use of ARP spoofing for Man-in-the-middle attacks.                                                                                                                         |      2     |
| local-dns                                                                                | DNS spoofing and cache poisoning on a local area network.  Derived from the SEED lab.                                                                                      |      3     |
| snort                                                                                    | Use of snort for network intrusion detection                                                                                                                               |      2     |
| dmz-lab                                                                                  | Set up a DMZ for an enterprise.                                                                                                                                            |      2     |
| radius                                                                                   | Use a Radius authentication service to authenticate network devices.                                                                                                       |      2     |
| ldap                                                                                     | Authenticate users of Linux servers using an LDAP service.                                                                                                                 |      2     |
| bird-bgp                                                                                 | Explore the Gateway Border Protocol and configure a BGP router.                                                                                                            |      2     |
| bird-ospf                                                                                | Explore the Open Shortest Path First router protocol and use it to create a spoofed website.                                                                               |      2     |
| Also see crypto labs, e.g., ssh, vpn and ssl labs.  And Network Traffic Analysis  below. |                                                                                                                                                                            |            |




|                                                              | Network Traffic Analysis                                                                                                            |            |
|--------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|------------|
| Lab                                                          | Description                                                                                                                         | difficulty |
| pcapanalysis                                                 | The tshark network traffic analysis tool is used to identify and display a specific network packet containing a plaintext password. |      2     |
| wireshark-intro                                              | Introduction to the use of Wireshark analyze network traffic.                                                                       |      2     |
| packet-introspection                                         | Use Wireshark for more advanced analysis of network traffic                                                                         |      3     |
| pcap-lib                                                     | Develop programs using the PCAP library to analyze an unknown packet capture.                                                       |      3     |
| netflow                                                      | Explore the NetFlow network traffic protocol and data record type using the CMU SiLK software suite.                                |      3     |
| Also see the Industrial Control System traffic analysis labs |                                                                                                                                     |            |





|            | Crypto Labs                                                                                                   |            |
|------------|---------------------------------------------------------------------------------------------------------------|------------|
| Lab        | Description                                                                                                   | difficulty |
| macs-hash  | Exploration of cryptographic hashes and the potential for hash collisions.                                    |      2     |
| onewayhash |  Introduction to generating cryptographic hashes using the openssl utility.                                   |      1     |
| pubkey     | Explore public key certificates from a variety of web sites                                                   |      1     |
| sshlab     | Use of a public/private key pair to access a server via ssh.                                                  |      1     |
| ssh-agent  | Use an SSH agent to manage your private key and avoid retyping your passphase                                 |      1     |
| ssl        | Use of SSL to authenticate both sides of a connection, includes creating and signing certificates using a CA. |            |
| symkeylab  |  Exploration of symmetric key encryption modes.                                                               |      1     |
| vpnlab     |  Example use of OpenVPN to protect network traffic.                                                           |      2     |
| vpnlab2    |  Similar to vpnlab, but with the use of a vpn gateway.                                                        |      2     |



|            | Web Security Labs                                                                        |            |
|------------|------------------------------------------------------------------------------------------|------------|
| Lab        | Description                                                                              | difficulty |
| webtrack   | Illustrates web tracking techniques and the role of ad servers, derived from a SEED lab. |      1     |
| xforge     |  Cross Site Request Forgery with a vulnerable web site, derived from a SEED lab.         |      2     |
| xsite      |  Cross site scripting attacks on a vulnerable web server, derived from a SEED lab.       |      2     |
| sql-inject |  SQL injection attacks and countermeasures, derived from a SEED lab.                     |      2     |



|                                                          | System Security & Operations                                                              |            |
|----------------------------------------------------------|-------------------------------------------------------------------------------------------|------------|
| Lab                                                      | Description                                                                               | difficulty |
| acl                                                      | Acess Control Lists (ACLs) on Linux                                                       |      2     |
| db-access                                                | Control sharing of information within an SQL database per an information security policy. |      2     |
| backups2                                                 | Using tar and dump/restore for file backups, including remote backups.                    |      1     |
| capabilities                                             | Use of Linux capabilites to limit program privileges.                                     |      2     |
| sys-log                                                  | System log basic usage and configuration on an Ubuntu system.                             |      2     |
| centos-log2                                              |  System log basic usage and configuration on a CentOS system.                             |      2     |
| file-deletion                                            | Data recovery from deleted files within EXT2 and NTFS file systems.                       |      2     |
| file-integrity                                           | File integrity checking and intrustion detetion with AIDE                                 |      2     |
| pass-crack                                               |  Introduction to passwords and elementary cracking schemes.                               |      2     |
| denyhost                                                 | Use of the denyhost utility to block brute force attacks on SSH                           |      2     |
| nix-commands                                             | Introduction to Linux and shell commands.                                                 |      1     |
| Also see ldap, radius, snort and iptables in Networking. |                                                                                           |            |



|                                                                                  | Industrial Control System Security                                                             |            |
|----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|------------|
| Lab                                                                              | Description                                                                                    | difficulty |
| softplc                                                                          | Program a software-based programmable logic controller (PLC)                                   |      3     |
| plc-forensics                                                                    |  Forensic analysis of a PLC session from a rouge client.                                       |      2     |
| plc-forensics-adv                                                                | Forensic analysis of a PLC session from a rouge client, including CIP & EtherNet/IP protocols. |      4     |
| plc                                                                              | Simulated example of a vulnerable Programmable Logic Controller system.                        |      2     |
| plc-app                                                                          | Application firewall and whitelisting to protect a PLC.                                        |      2     |
| iptables-ics                                                                     | Use iptables to limit traffic destined for a PLC through a firewall.                           |      2     |
| grassmarlin                                                                      | Introduction to the GrassMarlin SCADA/ICS network discovery tool.                              |      2     |
| plc-traffic                                                                      | Use the GrassMarlin tool to view traffic you generate interacting with a PLC.                  |      2     |
| Also see the ssl; radius and ldap labs for authentication of devices and people. |                                                                                                |            |



|            | Miscellaneous                                                                |   |
|------------|------------------------------------------------------------------------------|---|
| Lab        | Description                                                                  |   |
| cyberciege | The CyberCIEGE video game.                                                   |   |
| quantum    | Explores quantum algorithms: (1) teleportation; and, (2) Grover's algorithm. |   |
