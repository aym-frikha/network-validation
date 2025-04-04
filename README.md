# Network Firewall Validation Tool

This tool is designed to validate network connectivity based on a matrix of hosts and firewall rules defined in a YAML configuration file. It tests whether the required ports between different networks are open using SSH, netcat, and temporary listeners.

## Features

- Validates TCP and UDP connectivity between defined host interfaces
- Uses both system SSH and Paramiko for remote access
- Supports parallel validation to speed up the process
- Generates detailed and summary reports in CSV and TXT formats
- Can sample tests if the number of checks exceeds 100

## Files

- `validate.py`: The main validation script.
- `matrix.yaml`: Sample configuration file containing hosts, networks, and firewall rules.

## Requirements

- Python 3.6+
- Required Python packages:
  - `pyyaml`
  - `paramiko`
- `ssh`, `nc`, and `timeout` must be available on source and destination systems

## Configuration

The YAML file includes:

- `hosts`: Hostnames and their associated IPs grouped by network interface.
- `network_matrix`: Maps network interface names to CIDR blocks.
- `firewall_rules`: Defines allowed port/protocol combinations between networks.

### Example structure

```yaml
hosts:
  my-host-1:
    mgmt-net: 192.168.1.10

network_matrix:
  mgmt-net: 192.168.1.0/24

firewall_rules:
  "mgmt-net->mgmt-net":
    - port: 22
      protocol: tcp
```

## Usage

```bash
python3 validate.py matrix.yaml --output results.csv --ssh-key ~/.ssh/id_rsa --ssh-user ubuntu --parallel 5
```

### Parameters

- `matrix.yaml`: Path to the configuration file
- `--output`: Output CSV report path (default: `network_validation_report.csv`)
- `--ssh-key`: Path to the SSH private key
- `--ssh-user`: SSH username (default: `ubuntu`)
- `--parallel`: Number of concurrent tests to run (default: 3)

## Output

1. **CSV Report**: Detailed results of each tested connection.
2. **Summary TXT**: Statistics and top failing connections.

## Example Output

```csv
Source Host,Source IP,Destination Host,Destination IP,Port,Protocol,Status,Error
juju-ctl-1,100.111.128.2,COS-1,100.111.128.114,443,tcp,Open,
```

```txt
Summary of Results:
  Total connections tested: 50
  Open connections: 48 (96.0%)
  Closed connections: 2 (4.0%)

Top failing host pairs:
  juju-ctl-1->COS-3: 2/5 failed
```

## License

This project is open-source and available under the MIT License.
