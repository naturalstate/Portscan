from scapy.all import *
import ipaddress


print(r"""\                                                        
   ________________  ___.__. ______ ____ _____    ____  
  / ___\_  __ \__  \<   |  |/  ___// ___\\__  \  /    \ 
 / /_/  >  | \// __ \\___  |\___ \\  \___ / __ \|   |  \
 \___  /|__|  (____  / ____/____  >\___  >____  /___|  /
/_____/            \/\/         \/     \/     \/     \/

                    SECURITY SCANNER

""")


ports = [22,25,80,53,443,445,8080,8443]
sport = input("Port to Scan from: \r\n")
#make this input an array to process
#ports = int(input("Enter ports to scan: \r\n"))

#Add feature to automatically find local in for like Gateway, etc, WIFI passwords

def scanSYN(host):
    ans,unans = sr(
        IP(dst=host)/
        TCP(sport=33333,dport=ports,flags="S")
        ,timeout=2,verbose=0)
    print("Open ports for host %s\r\n" % host)
    for (s,r,) in ans:
        if s[TCP].dport == r[TCP].sport and r[TCP].flags=="SA":
            print(s[TCP].dport)
    
def DNSScan(host):
    ans,unans = sr(
        IP(dst=host)/
        UDP(dport=53)/
        DNS(rd=1,qd=DNSQR(qname="www.google.com"))
        ,timeout=2,verbose=0)
    if ans and ans[UDP]:
        print("DNS query for %s\r\n"%host)

host = input("Enter the host to scan: \r\n")
try:
    ipaddress.ip_address(host)
except:
    print("Invalid host")
    exit(-1)

scanSYN(host)
DNSScan(host)
            

    