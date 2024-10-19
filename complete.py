import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess
import threading
import logging
import re
import json

# Set up logging for firewall actions
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')
firewall_logger = logging.getLogger()

# Set up logging for all traffic
traffic_logger = logging.getLogger('TrafficLogger')
traffic_handler = logging.FileHandler('traffic.log')
traffic_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(message)s')
traffic_handler.setFormatter(formatter)
traffic_logger.addHandler(traffic_handler)

class FirewallGUI:
    def __init__(self, master):
        self.master = master
        master.title("Firewall Management")
        master.geometry("1920x1080")  # Set the GUI size to 1920x1080

        # Create the main sections
        self.create_network_configuration_section()
        self.create_firewall_rule_management_section()
        self.create_remove_rule_section()

        # Create the rule viewing and traffic monitoring section
        self.create_monitoring_section()

        # Start monitoring traffic as soon as the program starts
        self.start_traffic_monitoring()

        # Automatically show rules when the program starts
        self.view_rules()

    def create_network_configuration_section(self):
        
        # Frame for network configuration
        self.network_frame = tk.Frame(self.master)
        self.network_frame.pack(pady=10)

        # Network Configuration Section
        self.network_label = tk.Label(self.network_frame, text="NETWORK CONFIGURATION", font=("Helvetica", 16))
        self.network_label.grid(row=0, columnspan=8, pady=5)

        # Source IP and Destination IP (first row)
        tk.Label(self.network_frame, text="Source IP:").grid(row=1, column=0, padx=10, pady=2)
        self.source_entry = tk.Entry(self.network_frame)
        self.source_entry.grid(row=1, column=1, padx=10, pady=2)
        self.source_entry.bind("<KeyRelease>", self.suggest_protocol)  # Bind key release for suggestions

        tk.Label(self.network_frame, text="Destination IP:").grid(row=1, column=2, padx=10, pady=2)
        self.dest_entry = tk.Entry(self.network_frame)
        self.dest_entry.grid(row=1, column=3, padx=10, pady=2)
        self.dest_entry.bind("<KeyRelease>", self.suggest_protocol)  # Bind key release for suggestions

        # Subnet Masks (second row)
        tk.Label(self.network_frame, text="Source Subnet:").grid(row=2, column=0, padx=10, pady=2)
        self.source_subnet_entry = tk.Entry(self.network_frame)
        self.source_subnet_entry.grid(row=2, column=1, padx=10, pady=2)
        self.source_subnet_entry.insert(0, "255.255.255.255")  # Default value
        self.source_subnet_entry.bind("<KeyRelease>", self.suggest_protocol)  # Bind key release for suggestions

        tk.Label(self.network_frame, text="Destination Subnet:").grid(row=2, column=2, padx=10, pady=2)
        self.dest_subnet_entry = tk.Entry(self.network_frame)
        self.dest_subnet_entry.grid(row=2, column=3, padx=10, pady=2)
        self.dest_subnet_entry.insert(0, "255.255.255.255")  # Default value
        self.dest_subnet_entry.bind("<KeyRelease>", self.suggest_protocol)  # Bind key release for suggestions

        # Port and Protocol (third row)
        tk.Label(self.network_frame, text="Port:").grid(row=3, column=0, padx=10, pady=2)
        self.port_entry = tk.Entry(self.network_frame)
        self.port_entry.grid(row=3, column=1, padx=10, pady=2)
        self.port_entry.bind("<KeyRelease>", self.suggest_protocol)  # Bind key release to suggest_protocol

        tk.Label(self.network_frame, text="Protocol:").grid(row=3, column=2, padx=10, pady=2)

        # Protocol dropdown for manual selection
        self.protocol_var = tk.StringVar(self.network_frame)
        self.protocol_var.set("TCP")  # Default protocol
        self.protocol_menu = tk.OptionMenu(self.network_frame, self.protocol_var, "TCP", "UDP")
        self.protocol_menu.grid(row=3, column=3, padx=10, pady=2)

        # Suggested protocol label on a new row
        self.suggestion_label = tk.Label(self.network_frame, text="", width=80)  # Increased width for better visibility
        self.suggestion_label.grid(row=4, columnspan=8, pady=2)  # Spanning across columns for center alignment

    def create_firewall_rule_management_section(self):
        # Frame for firewall rule management
        self.rule_management_frame = tk.Frame(self.master)
        self.rule_management_frame.pack(pady=10)

        # Firewall Rule Management Section
        self.rule_label = tk.Label(self.rule_management_frame, text="FIREWALL RULE MANAGEMENT", font=("Helvetica", 16))
        self.rule_label.grid(row=0, columnspan=2, pady=5)

        # Buttons for rule management
        self.add_button = tk.Button(self.rule_management_frame, text="Accept Rule", command=self.add_rule, fg="#00FF00")
        self.add_button.grid(row=1, column=0, padx=10, pady=2)

        self.block_button = tk.Button(self.rule_management_frame, text="Block Rule", command=self.block_rule, fg="#FF0000")
        self.block_button.grid(row=1, column=1, padx=10, pady=2)

        # Save and upload rules buttons
        self.save_button = tk.Button(self.rule_management_frame, text="Save Rules", command=self.save_rules)
        self.save_button.grid(row=2, column=0, padx=10, pady=2)

        self.upload_button = tk.Button(self.rule_management_frame, text="Upload & Apply Rules", command=self.upload_and_apply_rules)
        self.upload_button.grid(row=2, column=1, padx=10, pady=2)

    def create_remove_rule_section(self):
        # Frame for remove rule section
        self.remove_rule_frame = tk.Frame(self.master)
        self.remove_rule_frame.pack(pady=10)

        # Remove Rule Section
        self.remove_rule_label = tk.Label(self.remove_rule_frame, text="REMOVE RULE SECTION", font=("Helvetica", 16))
        self.remove_rule_label.grid(row=0, columnspan=2, pady=5)

        # Action dropdown for selecting remove action
        self.action_var = tk.StringVar(self.remove_rule_frame)
        self.action_var.set("ACCEPT")  # Default action
        self.action_menu = tk.OptionMenu(self.remove_rule_frame, self.action_var, "ACCEPT ", "DROP")
        self.action_menu.grid(row=1, column=0, padx=10, pady=2)

        # Remove Rule button (center aligned)
        self.remove_button = tk.Button(self.remove_rule_frame, text="Remove Rule", command=self.remove_rule, fg="#AA0000")
        self.remove_button.grid(row=1, column=1, padx=10, pady=2)  # Right next to action menu

        # Remove All Rules button
        self.remove_all_button = tk.Button(self.remove_rule_frame, text="Remove All Rules", command=self.confirm_remove_all_rules, fg="#FF0000")
        self.remove_all_button.grid(row=2, columnspan=2, pady=5)  # Center aligned in the next row
    def create_monitoring_section(self):
        # Frame for rules and traffic monitoring section
        self.monitoring_frame = tk.Frame(self.master)
        self.monitoring_frame.pack(side="bottom", fill="both", expand=True)

        # Text widget to display firewall rules
        self.rules_text = tk.Text(self.monitoring_frame, height=10)
        self.rules_text.pack(expand=False, fill="both", pady=2)

        # Add topic label for traffic window
        self.traffic_window_topic_label = tk.Label(self.monitoring_frame, text="TRAFFIC MONITORING LOG", font=("Helvetica", 14))
        self.traffic_window_topic_label.pack(pady=5)

        # Text widget to display traffic logs
        self.traffic_text = tk.Text(self.monitoring_frame, height=15)
        self.traffic_text.pack(expand=True, fill="both", pady=2)

        # Configure tags for colors in traffic text
        self.traffic_text.tag_config('time', foreground='blue')
        self.traffic_text.tag_config('source', foreground='green')
        self.traffic_text.tag_config('destination', foreground='red')
        self.traffic_text.tag_config('port', foreground='orange')
        self.traffic_text.tag_config('protocol', foreground='purple')

    def run_command(self, command):
        # Function to run a shell command and return the output
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
            firewall_logger.info(f"Executed command: {command}")
            return output.decode()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Command failed: {e.output.decode()}")
            return None

    def validate_ip(self, ip): 
        # Validate IP address format
        pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        return pattern.match(ip) is not None

    def validate_subnet(self, subnet):
        # Validate subnet mask format
        pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        return pattern.match(subnet) is not None

    def validate_port(self, port):
        # Validate port number
        return port.isdigit() and 1 <= int(port) <= 65535
    
    def suggest_protocol(self, event=None):
        # Common TCP and UDP ports
        tcp_ports = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 23: "Telnet"}
        udp_ports = {53: "DNS", 67: "DHCP", 123: "NTP", 500: "IPSec", 161: "SNMP"}

        suggestions = []
        source_ip = self.source_entry.get()
        dest_ip = self.dest_entry.get()
        source_subnet = self.source_subnet_entry.get()
        dest_subnet = self.dest_subnet_entry.get()
        port = self.port_entry.get()

        # Validate IP and Subnet
        if source_ip and not self.validate_ip(source_ip):
            suggestions.append("Invalid Source IP format")
        if dest_ip and not self.validate_ip(dest_ip):
            suggestions.append("Invalid Destination IP format")
        if source_subnet and not self.validate_subnet(source_subnet):
            suggestions.append("Invalid Source Subnet format")
        if dest_subnet and not self.validate_subnet(dest_subnet):
            suggestions.append("Invalid Destination Subnet format")
        
        # Validate and Suggest Protocol Based on Port Number
        if port and self.validate_port(port):
            port_number = int(port)
            if port_number in tcp_ports:
                suggestions.append(f"Suggested Protocol: TCP ({tcp_ports[port_number]})")
            elif port_number in udp_ports:
                suggestions.append(f"Suggested Protocol: UDP ({udp_ports[port_number]})")
            elif port_number in range(1, 1024):
                suggestions.append("Suggested Protocol: TCP/UDP (Well-known ports)")
            elif port_number in range(1024, 49152):
                suggestions.append("Suggested Protocol: TCP (Registered ports)")
            else:
                suggestions.append("Suggested Protocol: UDP (Dynamic ports)")
        else:
            suggestions.append("Invalid Port number (1-65535)")

        # Update suggestion label
        self.suggestion_label.config(text="; ".join(suggestions) if suggestions else "", fg="#0000AA")

    def add_rule(self):
        # Function to add a firewall rule
        source_ip = self.source_entry.get()
        source_subnet = self.source_subnet_entry.get()
        dest_ip = self.dest_entry.get()
        dest_subnet = self.dest_subnet_entry.get()
        port = self.port_entry.get()
        protocol = self.protocol_var.get()  # Get selected protocol

        cmd = f"sudo iptables -A INPUT -p {protocol}"
        if source_ip:
            cmd += f" -s {source_ip}/{source_subnet}"  # Use CIDR notation for subnet
        if dest_ip:
            cmd += f" -d {dest_ip}/{dest_subnet}"  # Use CIDR notation for subnet
        if port:
            cmd += f" --dport {port}"
        cmd += " -j ACCEPT"

        firewall_logger.info(f"Allowing rule: {cmd}")
        self.run_command(cmd)

        # Refresh rules after adding
        self.view_rules()

    def block_rule(self):
        # Function to block a firewall rule
        source_ip = self.source_entry.get()
        source_subnet = self.source_subnet_entry.get()
        dest_ip = self.dest_entry.get()
        dest_subnet = self.dest_subnet_entry.get()
        port = self.port_entry.get()
        protocol = self.protocol_var.get()  # Get selected protocol

        cmd = f"sudo iptables -A INPUT -p {protocol}"
        if source_ip:
            cmd += f" -s {source_ip}/{source_subnet}"  # Use CIDR notation for subnet
        if dest_ip:
            cmd += f" -d {dest_ip}/{dest_subnet}"  # Use CIDR notation for subnet
        if port:
            cmd += f" --dport {port}"
        cmd += " -j DROP"

        firewall_logger.info(f"Blocking rule: {cmd}")
        self.run_command(cmd)

        # Refresh rules after blocking
        self.view_rules()

    def remove_rule(self):
        # Function to remove a firewall rule
        source_ip = self.source_entry.get()
        source_subnet = self.source_subnet_entry.get()
        dest_ip = self.dest_entry.get()
        dest_subnet = self.dest_subnet_entry.get()
        port = self.port_entry.get()
        protocol = self.protocol_var.get()  # Get selected protocol

        cmd = f"sudo iptables -D INPUT -p {protocol}"
        if source_ip:
            cmd += f" -s {source_ip}/{source_subnet}"  # Use CIDR notation for subnet
        if dest_ip:
            cmd += f" -d {dest_ip}/{dest_subnet}"  # Use CIDR notation for subnet
        if port:
            cmd += f" --dport {port}"
        cmd += " -j ACCEPT"

        firewall_logger.info(f"Removing rule: {cmd}")
        self.run_command(cmd)

        # Refresh rules after removing
        self.view_rules()

    def confirm_remove_all_rules(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to remove all rules?"):
            self.remove_all_rules()

    def remove_all_rules(self):
        # Function to remove all firewall rules
        cmd = "sudo iptables -F"
        firewall_logger.info("Removing all firewall rules")
        self.run_command(cmd)

        # Refresh rules after clearing
        self.view_rules()

    def view_rules(self):
        # Function to display the current iptables rules
        output = self.run_command("sudo iptables -L")
        if output:
            self.rules_text.delete(1.0, tk.END)
            self.rules_text.insert(tk.END, output)

    def save_rules(self):
        # Function to save the current iptables rules to a JSON file
        output = self.run_command("sudo iptables -S")
        if output:
            rules = self.parse_iptables_output(output)
            if not rules:
                messagebox.showerror("Error", "No rules found to save.")
                return
            
            file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
            if file_path:
                try:
                    with open(file_path, 'w') as file:
                        json.dump(rules, file, indent=4)
                    messagebox.showinfo("Success", f"Rules saved to {file_path}")
                    firewall_logger.info(f"Saved firewall rules to {file_path}")
                except IOError as e:
                    messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                    firewall_logger.error(f"Failed to save file: {str(e)}")

    def parse_iptables_output(self, output):
    # Function to parse iptables output into a structured format
        rules = []
        for line in output.splitlines():
            match = re.match(r'-A (\S+) -p (\S+)(?: -s (\S+))?(?: -d (\S+))?(?: --dport (\d+))?(?: -j (\S+))?', line)
            if match:
                chain, protocol, source, destination, dport, action = match.groups()
                rules.append({
                    'chain': chain,
                    'protocol': protocol,
                    'source': source or 'any',
                    'destination': destination or 'any',
                    'dport': dport or 'any',
                    'action': action
                })
        return rules
        self.view_rules()


    def upload_and_apply_rules(self):
        # Function to upload a JSON file and apply the firewall rules
        file_path = filedialog.askopenfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'r') as file:
                rules = json.load(file)
                self.apply_rules(rules)
                messagebox.showinfo("Success", f"Rules applied from {file_path}")
                firewall_logger.info(f"Applied firewall rules from {file_path}")

    def apply_rules(self, rules):
     # Function to apply firewall rules from a JSON file
     # First, clear all current rules
     self.run_command("sudo iptables -F")
     for rule in rules:
         cmd = f"sudo iptables -A {rule['chain']} -p {rule['protocol']}"
         if rule['source'] != 'any':
             cmd += f" -s {rule['source']}"
         if rule['destination'] != 'any':
             cmd += f" -d {rule['destination']}"
         if rule['dport'] != 'any':  # Make sure it's 'dport', not 'port' since iptables expects this.
             cmd += f" --dport {rule['dport']}"
         cmd += f" -j {rule['action']}"
         self.run_command(cmd)  # Run each command and check for errors
     self.view_rules()  # View the updated rules after applying
        
    def monitor_all_traffic(self):
        # Function to monitor all traffic using tcpdump
        command = ["sudo", "tcpdump", "-l", "-n"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        def update_traffic_output(self):
        # Assuming `lines` is a list of traffic output lines you want to process
         for line in lines:
            self.root.after(0, self.color_traffic_line, line.strip())        

        def update_traffic_output():
            self.traffic_text.config(state=tk.NORMAL)
            for line in process.stdout:
                traffic_logger.info(line.strip())  # Log each line of traffic
                self.color_traffic_line(line.strip())  # Call the function to color the line
                self.traffic_text.see(tk.END)  # Auto-scroll to the latest line
            self.traffic_text.insert(tk.END, line + '\n')
            self.traffic_text.config(state=tk.DISABLED)
        threading.Thread(target=update_traffic_output, daemon=True).start()

    def color_traffic_line(self, line):
        # Function to color code the traffic line
        parts = line.split()  # Split line into parts

        if len(parts) < 7:  # Not enough parts to analyze
            return

        time = parts[0] + " " + parts[1]  # Combine time parts
        source_ip = parts[2]  # Assuming source IP is the third part
        dest_ip = parts[4]  # Assuming destination IP is the fifth part
        port = parts[6] if len(parts) > 6 else "N/A"  # Port number if available
        protocol = parts[5] if len(parts) > 5 else "N/A"  # Protocol if available

        # Insert time, source IP, destination IP, port, and protocol with different colors
        self.traffic_text.config(state=tk.NORMAL)
        self.traffic_text.insert(tk.END, time + " ", 'time')  # Time in blue
        self.traffic_text.insert(tk.END, source_ip + " ", 'source')  # Source IP in green
        self.traffic_text.insert(tk.END, dest_ip + " ", 'destination')  # Destination IP in red
        self.traffic_text.insert(tk.END, "Port: " + port + " ", 'port')  # Port in orange
        self.traffic_text.insert(tk.END, "Protocol: " + protocol + "\n", 'protocol')  # Protocol in purple
        self.traffic_text.config(state=tk.DISABLED)

    def start_traffic_monitoring(self):
        # Start monitoring traffic in a separate thread
        threading.Thread(target=self.monitor_all_traffic, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()
