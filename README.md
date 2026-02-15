# InProd Ansible Collection for Genesys Cloud

![Tests](https://github.com/inprod/ansible_genesys/actions/workflows/tests.yml/badge.svg)
![License](https://img.shields.io/badge/license-AGPL--3.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Ansible](https://img.shields.io/badge/ansible-%3E%3D2.9-blue)
![Version](https://img.shields.io/badge/collection-2.0.0-green)

## Description

This collection provides an Ansible module for managing Genesys Cloud configuration through [InProd](https://www.inprod.io) changesets. Unlike limited tools such as the Genesys Cloud CLI tool Archy, This module can apply configuration changes across all object types within Genesys Cloud and it not limited in scope such as the Genesys Cloud cli tool 'Archy'.

Designed for use within CI/CD pipelines, this collection enables Genesys Cloud configuration to be stored in version control and deployed across multiple Genesys Cloud environments using orchestration tools such as Jenkins, GitHub Actions, or similar platforms.

### Workflow

1. **Design** the changeset within InProd and validate it against each target Genesys Cloud environment. Using variables and queries, all environment differences and naming conventions can be catered for.
2. **Export** the changeset as JSON or YAML and check it into version control.
3. **Deploy** using your standard CI/CD workflow for testing and approval, using this Ansible module to execute the change from version control.

Please refer to the [InProd documentation](https://www.inprod.io) for details on how changesets can manage the Genesys Cloud platform.

### Modules

| Name | Description |
|------|-------------|
| `inprod.genesys_cloud.changeset` | Validate and execute InProd changesets against Genesys Cloud environments |

The `changeset` module supports the following actions:

| Action | Description |
|--------|-------------|
| `validate` | Validate a changeset by passing in the changeset ID |
| `validate_json` | Validate a changeset supplied as JSON data |
| `validate_yaml` | Validate a changeset supplied as YAML data |
| `execute` | Execute a changeset by passing in the changeset ID |
| `execute_json` | Execute a changeset supplied as JSON data |
| `execute_yaml` | Execute a changeset supplied as YAML data |

## Requirements

- Python 3.8+
- Ansible >= 2.9

## Installation

### From Source (Development)

Clone the repository:

```bash
git clone https://github.com/inprod/ansible_genesys.git
cd ansible_genesys
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```yaml
- name: Validate a changeset
  inprod.genesys_cloud.changeset:
    host: 'your-company.inprod.io'
    action: 'validate'
    api_key: '{{ vault_inprod_api_key }}'
    changeset_id: '125'
    ssl: true

- name: Execute a changeset
  inprod.genesys_cloud.changeset:
    host: 'your-company.inprod.io'
    action: 'execute'
    api_key: '{{ vault_inprod_api_key }}'
    changeset_id: '125'
    ssl: true
```

### Using Ansible Vault

Store your API key securely with Ansible Vault:

```bash
ansible-vault create group_vars/all/vault.yml
```

Then reference in your playbook:

```yaml
- name: Execute changeset with vault
  inprod.genesys_cloud.changeset:
    host: '{{ inprod_host }}'
    action: 'execute'
    api_key: '{{ vault_inprod_api_key }}'
    changeset_id: '{{ changeset_id }}'
    ssl: true
```

## Development

### Setup Development Environment

```bash
python3 -m venv .
source bin/activate  # On Windows: .\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

### Running Tests

Unit tests:

```bash
pytest tests/unit/ -v
```

Integration tests:

```bash
ansible-playbook tests/integration/targets/inprod/main.yml -vvv
```

### Building the Collection

```bash
ansible-galaxy collection build
```

This creates a tarball that can be distributed or published to Ansible Galaxy.

## License

AGPL-3.0 - see [LICENSE](LICENSE) for details.

## Trademark & Affiliation

Genesys® and Genesys Cloud™ are trademarks of [Genesys](https://www.genesys.com). 
This project is not affiliated with, endorsed by, or sponsored by Genesys.

All other trademarks are the property of their respective owners.