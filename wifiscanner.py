#!/usr/bin/env python3
import subprocess
import shutil
import sys
import time

class WirelessAuditor:
    def __init__(self):
        self.unsecured_networks = []
        self.secure_count = 0

    def verify_environment(self):
        """Ensures the host is running a supported Linux configuration."""
        if not sys.platform.startswith("linux"):
            print("[!] Error: This architecture-specific tool must be run on Linux.")
            sys.exit(1)
        if not shutil.which("nmcli"):
            print("[!] Error: 'nmcli' (NetworkManager CLI) is missing. Install it to use this tool.")
            sys.exit(1)

    def scan_airwaves(self):
        """Forces an ambient hardware rescan and processes network structures."""
        print("=" * 60)
        print("        AUTOMATED UNSECURED WIRELESS RECONNAISSANCE         ")
        print("=" * 60)
        print("[*] Initializing wireless adapter rescan... Please wait.")
        
        try:
            # Force network manager to request fresh beacon frames from nearby APs
            subprocess.run(["nmcli", "dev", "wifi", "rescan"], capture_output=True, timeout=8)
            time.sleep(1) # Let the hardware cache settle
            
            # Query exact parameters using a standardized colon-delimited output format
            cmd = ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            lines = proc.stdout.strip().split("\n")
            seen_bssids = set() # Avoid duplicating dual-band or multi-channel routers

            for line in lines:
                if not line or ":" not in line:
                    continue
                
                # FIX: Protect escaped colons in MAC addresses before splitting fields
                safe_line = line.replace(r"\:", "|")
                parts = safe_line.split(":")
                if len(parts) < 5:
                    continue
                    
                # Reconstruct SSID safely in case the name contains a colon character
                ssid = ":".join(parts[:-4]).strip().replace("|", ":")
                
                # Extract fields using negative indices relative to the end of the list
                bssid = parts[-4].strip().replace("|", ":")
                channel = parts[-3].strip()
                signal = parts[-2].strip()
                security = parts[-1].strip()

                if not ssid or bssid in seen_bssids:
                    continue
                seen_bssids.add(bssid)

                # Isolate entirely open/unencrypted targets
                if security == "--" or not security:
                    self.unsecured_networks.append({
                        "ssid": ssid,
                        "bssid": bssid,
                        "channel": channel,
                        "signal_strength": f"{signal}%"
                    })
                else:
                    self.secure_count += 1
                    
        except subprocess.CalledProcessError as e:
            print(f"[-] Interface failure: Ensure your Wi-Fi card is enabled. Error: {e}")
            sys.exit(1)

    def print_report(self):
        """Outputs a clean tactical intelligence matrix to the terminal screen."""
        print(f"[+] Scan Complete. Evaluated {len(self.unsecured_networks) + self.secure_count} total access points.")
        print(f"[+] Found {self.secure_count} securely encrypted networks.")

        if self.unsecured_networks:
            # Sort targets logically so the strongest signals float to the top
            self.unsecured_networks.sort(key=lambda x: int(x["signal_strength"].replace("%","")), reverse=True)
            
            print("\n[⚠️] TARGETS IDENTIFIED: Detected Unsecured Open Wireless Networks:")
            print("-" * 60)
            for ap in self.unsecured_networks:
                print(f"[➔] SSID:       {ap['ssid']}")
                print(f"    BSSID:      {ap['bssid']}")
                print(f"    Channel:    {ap['channel']}")
                print(f"    Signal:     {ap['signal_strength']}")
                print("-" * 60)
        else:
            print("\n[🎉] EXCELLENT ENVIRONMENTAL POSTURE: Zero unsecured networks detected within range.\n")

if __name__ == "__main__":
    auditor = WirelessAuditor()
    auditor.verify_environment()
    auditor.scan_airwaves()
    auditor.print_report()
