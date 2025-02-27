#!/usr/bin/env python3
import argparse
import yaml
import csv
import threading
import paramiko
import socket
import time
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor

class NetworkValidator:
    def __init__(self, config_file, ssh_key=None, ssh_user="ubuntu"):
        self.ssh_key = ssh_key
        self.ssh_user = ssh_user
        self.results = []
        self.lock = threading.Lock()
        self.connections = {}  # Track active SSH connections

        # Load configuration
        try:
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)
                print(f"Configuration loaded from {config_file}")
        except Exception as e:
            print(f"Error loading configuration: {e}")
            raise

    def ssh_connect(self, host):
        """Connect to host via SSH using the most reliable method"""
        if host in self.connections:
            return self.connections[host]

        print(f"Connecting to {host}...")

        # Try system SSH first (most reliable)
        test_cmd = f"ssh -o BatchMode=yes -o ConnectTimeout=5 {self.ssh_user}@{host} echo 'Connected'"
        test_result = os.system(test_cmd + " > /dev/null 2>&1")

        if test_result == 0:
            self.connections[host] = "system_ssh"
            print(f"Successfully connected to {host} via system SSH")
            return "system_ssh"

        # Fall back to Paramiko
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                username=self.ssh_user,
                key_filename=self.ssh_key,
                timeout=5,
                allow_agent=True
            )
            self.connections[host] = client
            print(f"Successfully connected to {host} via Paramiko")
            return client
        except Exception as e:
            print(f"Failed to connect to {host}: {str(e)}")
            return None

    def run_ssh_command(self, host, command):
        """Run command via SSH using the appropriate method"""
        connection = self.ssh_connect(host)

        if not connection:
            return False, f"Could not connect to {host}"

        if connection == "system_ssh":
            # Use subprocess to run command via system SSH
            full_cmd = f"ssh {self.ssh_user}@{host} '{command}'"
            try:
                process = subprocess.run(
                    full_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10
                )
                output = process.stdout.decode('utf-8') + process.stderr.decode('utf-8')
                return process.returncode == 0, output
            except subprocess.TimeoutExpired:
                return False, "Command timed out"
            except Exception as e:
                return False, str(e)
        else:
            # Use Paramiko
            try:
                stdin, stdout, stderr = connection.exec_command(command, timeout=10)
                output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                exit_code = stdout.channel.recv_exit_status()
                return exit_code == 0, output
            except Exception as e:
                return False, str(e)

    def test_port_connectivity(self, src_ip, src_hostname, dst_ip, dst_hostname, port, protocol):
        """Test connectivity by setting up a temporary listener"""
        result = {
            'src_host': src_hostname,
            'src_ip': src_ip,
            'dst_host': dst_hostname,
            'dst_ip': dst_ip,
            'port': port,
            'protocol': protocol,
            'status': False,
            'error': None
        }

        # Step 1: Set up a temporary listener on destination
        if protocol.lower() == 'tcp':
            # For TCP, set up a netcat listener that times out after 10 seconds
            listener_cmd = f"(sudo timeout 10 nc -l {port} || true) > /dev/null 2>&1 &"
        else:
            # For UDP
            listener_cmd = f"(sudo timeout 10 nc -ul {port} || true) > /dev/null 2>&1 &"

        # Start listener
        print(f"Setting up listener on {dst_ip}:{port}/{protocol}")
        success, output = self.run_ssh_command(dst_ip, listener_cmd)

        if not success:
            result['error'] = f"Failed to set up listener: {output}"
            with self.lock:
                self.results.append(result)
            return result

        # Give the listener a moment to start
        time.sleep(1)

        # Step 2: Try to connect from source to destination
        if protocol.lower() == 'tcp':
            # Use netcat to test TCP connectivity
            test_cmd = f"nc -zv -w 5 {dst_ip} {port} 2>&1"
        else:
            # For UDP, send a test packet
            test_cmd = f"echo 'test' | nc -zuv -w 5 {dst_ip} {port} 2>&1"

        print(f"Testing {src_ip} -> {dst_ip}:{port}/{protocol}")
        success, output = self.run_ssh_command(src_ip, test_cmd)

        # Evaluate result
        if success or "succeeded" in output.lower() or "open" in output.lower():
            result['status'] = True
        else:
            result['error'] = output.strip()

        with self.lock:
            self.results.append(result)
        return result

    def validate_network(self, parallel=3):
        """Run firewall validation checks with proper temporary listeners"""
        tasks = []

        # Parse the firewall rules
        print("Building test tasks...")
        for network_pair, rules in self.config['firewall_rules'].items():
            src_network, dst_network = network_pair.split('->')

            # Find hosts on source network
            src_hosts = {}
            for hostname, interfaces in self.config['hosts'].items():
                if src_network in interfaces:
                    src_hosts[hostname] = interfaces[src_network]

            # Find hosts on destination network
            dst_hosts = {}
            for hostname, interfaces in self.config['hosts'].items():
                if dst_network in interfaces:
                    dst_hosts[hostname] = interfaces[dst_network]

            # For each source-destination pair, check ports
            for src_hostname, src_ip in src_hosts.items():
                for dst_hostname, dst_ip in dst_hosts.items():
                    if src_hostname == dst_hostname:
                        continue  # Skip self-to-self

                    for rule in rules:
                        if isinstance(rule, dict):
                            port = rule['port']
                            protocol = rule.get('protocol', 'tcp')

                            # Handle port ranges
                            if isinstance(port, str) and '-' in port:
                                start, end = map(int, port.split('-'))
                                # Just test a few sample ports from the range
                                sample_ports = [start, (start + end) // 2, end]
                                for p in sample_ports:
                                    tasks.append((src_ip, src_hostname, dst_ip, dst_hostname, p, protocol))
                            else:
                                tasks.append((src_ip, src_hostname, dst_ip, dst_hostname, int(port), protocol))
                        else:
                            # Simple port number
                            tasks.append((src_ip, src_hostname, dst_ip, dst_hostname, int(rule), 'tcp'))

        total_tasks = len(tasks)
        print(f"Starting validation of {total_tasks} connectivity tests...")

        # Limit the number of tests if there are too many
        if total_tasks > 100:
            import random
            tasks = random.sample(tasks, 100)
            print(f"Testing a sample of 100 connections out of {total_tasks}")

        # Execute tests with limited parallelism (too much parallelism causes SSH issues)
        completed = 0
        with ThreadPoolExecutor(max_workers=parallel) as executor:
            futures = []
            for args in tasks:
                futures.append(executor.submit(self.test_port_connectivity, *args))

            # Wait for tasks and show progress
            for future in futures:
                future.result()
                completed += 1
                if completed % 5 == 0:
                    print(f"Progress: {completed}/{len(tasks)} tests completed")

        print(f"All {len(tasks)} connectivity tests completed")
        return self.results

    def generate_report(self, output_file='network_validation_report.csv'):
        """Generate a CSV report of validation results"""
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Source Host', 'Source IP', 'Destination Host', 'Destination IP',
                        'Port', 'Protocol', 'Status', 'Error']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for result in self.results:
                writer.writerow({
                    'Source Host': result['src_host'],
                    'Source IP': result['src_ip'],
                    'Destination Host': result['dst_host'],
                    'Destination IP': result['dst_ip'],
                    'Port': result['port'],
                    'Protocol': result['protocol'],
                    'Status': 'Open' if result['status'] else 'Closed',
                    'Error': result['error'] or ''
                })

        # Generate a summary report
        summary_file = output_file.replace('.csv', '_summary.txt')
        with open(summary_file, 'w') as f:
            f.write("Network Validation Summary Report\n")
            f.write("===============================\n\n")

            # Overall statistics
            open_count = sum(1 for r in self.results if r['status'])
            closed_count = len(self.results) - open_count

            f.write(f"Total connections tested: {len(self.results)}\n")
            f.write(f"Open connections: {open_count} ({open_count/len(self.results)*100:.1f}%)\n")
            f.write(f"Closed connections: {closed_count} ({closed_count/len(self.results)*100:.1f}%)\n\n")

            # Results by host pair
            f.write("Results by Host Pair\n")
            f.write("------------------\n")

            host_pairs = {}
            for result in self.results:
                pair_key = f"{result['src_host']}->{result['dst_host']}"

                if pair_key not in host_pairs:
                    host_pairs[pair_key] = {'total': 0, 'open': 0, 'closed': 0}

                host_pairs[pair_key]['total'] += 1
                if result['status']:
                    host_pairs[pair_key]['open'] += 1
                else:
                    host_pairs[pair_key]['closed'] += 1

            # Write host pair summary
            for pair, stats in sorted(host_pairs.items()):
                open_pct = (stats['open'] / stats['total']) * 100 if stats['total'] > 0 else 0
                f.write(f"{pair}: {stats['open']}/{stats['total']} open ({open_pct:.1f}%)\n")

            f.write("\n")

            # Failed connection details
            if closed_count > 0:
                f.write("Failed Connection Details\n")
                f.write("------------------------\n")
                for result in sorted(self.results, key=lambda r: (r['src_host'], r['dst_host'], r['port'])):
                    if not result['status']:
                        f.write(f"{result['src_host']} ({result['src_ip']}) → ")
                        f.write(f"{result['dst_host']} ({result['dst_ip']}) ")
                        f.write(f"Port {result['port']}/{result['protocol']}")
                        if result['error']:
                            f.write(f" - Error: {result['error']}")
                        f.write("\n")

        print(f"Detailed report generated: {output_file}")
        print(f"Summary report generated: {summary_file}")

        # Print a condensed summary to console
        print("\nSummary of Results:")
        print(f"  Total connections tested: {len(self.results)}")
        print(f"  Open connections: {open_count} ({open_count/len(self.results)*100:.1f}%)")
        print(f"  Closed connections: {closed_count} ({closed_count/len(self.results)*100:.1f}%)")

        # Print failing host pairs
        failing_pairs = sorted(
            [(pair, stats) for pair, stats in host_pairs.items() if stats['closed'] > 0],
            key=lambda x: x[1]['closed'],
            reverse=True
        )[:5]

        if failing_pairs:
            print("\nTop failing host pairs:")
            for pair, stats in failing_pairs:
                print(f"  {pair}: {stats['closed']}/{stats['total']} failed")

def main():
    parser = argparse.ArgumentParser(description='Firewall Validation Tool')
    parser.add_argument('config', help='Path to YAML configuration file')
    parser.add_argument('--output', help='Output report file', default='network_validation_report.csv')
    parser.add_argument('--ssh-key', help='SSH private key file')
    parser.add_argument('--ssh-user', help='SSH username', default='ubuntu')
    parser.add_argument('--parallel', type=int, default=3, help='Number of parallel checks (keep low)')

    args = parser.parse_args()

    try:
        validator = NetworkValidator(args.config, args.ssh_key, args.ssh_user)
        validator.validate_network(parallel=args.parallel)
        validator.generate_report(args.output)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Generating report with partial results...")
        if 'validator' in locals():
            validator.generate_report(args.output)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
