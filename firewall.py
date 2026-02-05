
#!/usr/bin/env python3
# Ultra Simple Python Firewall for Ubuntu
import json
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
# Configuration
RULES_FILE = "firewall_rules.json"
class MiniFirewall:
    def **init**(self):
        self.rules = self.load_rules()
   
    def load_rules(self):
        try:
            with open(RULES_FILE) as f:
                return json.load(f)
        except:
            return []
   
    def save_rules(self):
        with open(RULES_FILE, 'w') as f:
            json.dump(self.rules, f)
   
    def add_rule(self, rule):
        self.rules.append(rule)
        self.save_rules()
   
    def check_packet(self, pkt):
        if IP not in pkt:
            return True
       
        for rule in self.rules:
            match = True
            if 'src_ip' in rule and pkt[IP].src != rule['src_ip']:
                match = False
            if 'dst_ip' in rule and pkt[IP].dst != rule['dst_ip']:
                match = False
            if 'proto' in rule:
                if rule['proto'] == 'tcp' and TCP not in pkt:
                    match = False
                elif rule['proto'] == 'udp' and UDP not in pkt:
                    match = False
            if match:
                print(f"Rule matched: {rule}")
                return rule['action'] == 'allow'
       
        return True # Default allow
def packet_handler(pkt):
    if firewall.check_packet(pkt):
        print(f"Allowing: {pkt.summary()}")
    else:
        print(f"Blocking: {pkt.summary()}")
def show_menu():
    print("\n1. Add Block Rule")
    print("2. Add Allow Rule")
    print("3. List Rules")
    print("4. Start Firewall")
    print("5. Exit")
def add_rule(action):
    rule = {'action': action}
    rule['src_ip'] = input("Source IP (enter for any): ") or None
    rule['dst_ip'] = input("Dest IP (enter for any): ") or None
    rule['proto'] = input("Protocol (tcp/udp/any): ").lower() or None
    firewall.add_rule(rule)
    print("Rule added!")
if **name** == "**main**":
    firewall = MiniFirewall()
   
    while True:
        show_menu()
        choice = input("Choose: ")
       
        if choice == '1':
            add_rule('block')
        elif choice == '2':
            add_rule('allow')
        elif choice == '3':
            print("\nCurrent Rules:")
            for i, rule in enumerate(firewall.rules, 1):
                print(f"{i}. {rule}")
        elif choice == '4':
            print("\nFirewall running (Ctrl+C to stop)...")
            sniff(prn=packet_handler, store=0)
        elif choice == '5':
            break
        else:
            print("Invalid choice")
