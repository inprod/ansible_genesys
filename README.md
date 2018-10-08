# Usage
Please refer to the InProd changeset documentation for details on how changesets can manage the Genesys Engage platform. To Learn more about Genesys DevOps and configuration management vist https://www.inprod.io


# Installation

Clone the repo locally
```
git clone git://github.com/inprod/ansible_genesys.git
```

## Module Install
Ansible must be made aware of this new module. There are multiple ways of
doing this depending on your requirements and environment.

* Ansible configuration file: `ansible.cfg`
* Environment variable: `ANSIBLE_LIBRARY`
* Command line parameter: `ansible-playbook --module-path [path]`

### Updating Ansible configuration
The preferred method of installation is to update the Ansible configuration with the module path. To include the path globally for all users, edit the /etc/ansible/ansible.cfg file and add library = `/path/to/module/` under the `[default]` section. For example:

```
[default]
library = /path/to/ansible_genesys/inprod
```

Note that the Ansible configuration file is read from several locations in the following order:

1. `ANSIBLE_CONFIG` environment variable path
1. `ansible.cfg` from the current directory
1. `.ansible.cfg` in the user home directory
1. `/etc/ansible/ansible.cfg`


### Ansible command line parameter
The module path can be overridden with an ansible-playbook command line parameter:

```
ansible-playbook --module-path /path/to/ansible_genesys/inprod playbook.yml
```

# Development

## Python 3
1. python3 -m venv .
1. curl https://bootstrap.pypa.io/get-pip.py | bin/python
1. bin/pip install ansible

## Python 2.7
1. easy_install pip
1. pip install virtualenv
1. virtualenv -p /usr/bin/python2.7 .
1. bin/pip install ansible


## Running tests
* bin/ansible-playbook ./inprod.yml -vvv
* bin/python inprod.py args.json -vvv
* The `-vvv` flag will display a full stack trace which is needed for debugging
