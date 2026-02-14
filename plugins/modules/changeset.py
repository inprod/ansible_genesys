#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from typing import Dict, Tuple, Any

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'InProd Solutions Pty Ltd'
}

DOCUMENTATION = '''
---
module: changeset
short_description: Use Ansible to call InProd Changesets
description:
    - Allows you to validate and execute Genesys Cloud changesets via the InProd API
    - Supports validation, execution, and JSON/YAML-based changeset operations
version_added: "2.9"
author: InProd Solutions Pty Ltd

options:
    host:
        description:
            - The hostname or IP address of the InProd service
        required: true
        type: str
    action:
        description:
            - The changeset action to perform
            - C(validate) - Validates a changeset without executing
            - C(execute) - Validates and executes a changeset
            - C(validate_json) - Validates a changeset defined in a JSON file
            - C(execute_json) - Executes a changeset defined in a JSON file
            - C(validate_yaml) - Validates a changeset defined in a YAML file
            - C(execute_yaml) - Executes a changeset defined in a YAML file
        required: true
        type: str
        choices: ['validate', 'execute', 'validate_json', 'execute_json', 'validate_yaml', 'execute_yaml']
    api_key:
        description:
            - API key for authentication with the InProd service
            - Use Ansible vault or other secret management to protect this value
        required: true
        type: str
        no_log: true
    changeset_id:
        description:
            - Changeset ID to validate or execute
            - Required when action is C(validate) or C(execute)
        type: str
        required: false
    file_path:
        description:
            - Absolute path to JSON or YAML file containing changeset configuration
            - Required when action is C(validate_json), C(execute_json), C(validate_yaml), or C(execute_yaml)
        type: str
        required: false
    ssl:
        description:
            - Enable SSL/HTTPS for connections to the InProd service
        type: bool
        default: true
    timeout:
        description:
            - HTTP request timeout in seconds
        type: int
        default: 30
    validate_certs:
        description:
            - Enable SSL certificate validation
        type: bool
        default: true

requirements:
    - "python >= 3.8"
    - "requests >= 2.25.0"

extends_documentation_fragment: []
'''

EXAMPLES = '''
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
    timeout: 60

- name: Execute changeset from JSON file
  inprod.genesys_cloud.changeset:
    host: 'your-company.inprod.io'
    action: 'execute_json'
    api_key: '{{ vault_inprod_api_key }}'
    file_path: '/path/to/execute.json'
    ssl: true

- name: Validate changeset from JSON file
  inprod.genesys_cloud.changeset:
    host: 'your-company.inprod.io'
    action: 'validate_json'
    api_key: '{{ vault_inprod_api_key }}'
    file_path: '/path/to/changeset.json'
    ssl: true

- name: Validate changeset from YAML file
  inprod.genesys_cloud.changeset:
    host: 'your-company.inprod.io'
    action: 'validate_yaml'
    api_key: '{{ vault_inprod_api_key }}'
    file_path: '/path/to/changeset.yml'
    ssl: true

- name: Execute changeset from YAML file
  inprod.genesys_cloud.changeset:
    host: 'your-company.inprod.io'
    action: 'execute_yaml'
    api_key: '{{ vault_inprod_api_key }}'
    file_path: '/path/to/changeset.yml'
    ssl: true
    timeout: 60

- name: Validate with custom timeout and certificate check
  inprod.genesys_cloud.changeset:
    host: 'inprod.example.com'
    action: 'validate'
    api_key: '{{ vault_inprod_api_key }}'
    changeset_id: '456'
    ssl: true
    timeout: 45
    validate_certs: true
'''

RETURN = r'''
message:
    description: The output message from the API operation
    type: str
    returned: always
    sample: "Change Set was executed successfully"
changed:
    description: Whether the changeset state was changed
    type: bool
    returned: always
    sample: true
'''


class InProdAPIClient:
    """Client for InProd API operations."""

    def __init__(
        self,
        hostname: str,
        api_key: str,
        ssl: bool = True,
        timeout: int = 30,
        validate_certs: bool = True
    ):
        """
        Initialize InProd API client.

        Args:
            hostname: InProd service hostname
            api_key: API key for authentication
            ssl: Use HTTPS if True
            timeout: Request timeout in seconds
            validate_certs: Validate SSL certificates if True
        """
        self.hostname = hostname
        self.api_key = api_key
        self.ssl = ssl
        self.timeout = timeout
        self.validate_certs = validate_certs
        self.session = requests.Session()
        self.session.verify = validate_certs

    @property
    def base_url(self) -> str:
        """Build base URL for API calls."""
        protocol = "https" if self.ssl else "http"
        return f"{protocol}://{self.hostname}"

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Handle API response and extract data.

        Args:
            response: Response object from requests library

        Returns:
            Parsed JSON response

        Raises:
            ValueError: If API returns error status
        """
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse API response: {str(e)}")

        if response.status_code not in (200, 201):
            error_msg = self._extract_errors(data)
            raise ValueError(
                f"API responded with HTTP {response.status_code} Error!\n{error_msg}"
            )

        return data

    @staticmethod
    def _extract_errors(response_data: Dict[str, Any]) -> str:
        """
        Extract error details from API response.

        Args:
            response_data: Parsed JSON response body

        Returns:
            Formatted error message string
        """
        result = []

        if isinstance(response_data, list):
            for error in response_data:
                if 'action_id' in error:
                    # Validation/changeset run response
                    if not error.get('errors'):
                        continue
                    action_errors = [
                        f"{k}: {' - '.join(v)}"
                        for (k, v) in error.get('errors', {}).items()
                    ]
                    msg = f"Action Id: {error['action_id']} {' - '.join(action_errors)}"
                else:
                    # JSON API error response
                    msg = "{}: {}".format(
                        error.get('source', {}).get('pointer', 'base'),
                        error.get('detail')
                    )
                result.append(msg)

        elif isinstance(response_data.get('errors'), dict):
            # Regular error message format
            for (key, val) in response_data.get('errors', {}).items():
                formatted_val = " - ".join(val) if isinstance(val, list) else val
                msg = f"{key}: {formatted_val}"
                result.append(msg)

        return "\n".join(result)

    @property
    def _headers(self) -> Dict[str, str]:
        """Build common headers for JSON API requests."""
        return {
            'Authorization': f"Api-Key {self.api_key}",
            'Content-Type': 'application/json'
        }

    @property
    def _yaml_headers(self) -> Dict[str, str]:
        """Build headers for YAML API requests."""
        return {
            'Authorization': f"Api-Key {self.api_key}",
            'Content-Type': 'application/x-yaml'
        }

    @staticmethod
    def _parse_validation_response(data: Any) -> Tuple[bool, bool, str]:
        """
        Parse validation response payload for errors and warnings.

        The API may return HTTP 200/201 even when validation fails.
        Errors are contained in the response payload.

        Args:
            data: Parsed JSON response (expected to be a list of action results)

        Returns:
            Tuple of (success, changed, message)
        """
        if not isinstance(data, list):
            return (True, False, "Change set validated correctly")

        errors = []
        warnings = []

        for action in data:
            action_id = action.get('action_id', 'unknown')

            for field, field_errors in action.get('errors', {}).items():
                for entry in field_errors:
                    for msg in entry.get('msg', []):
                        errors.append(f"Action {action_id} - {field}: {msg}")

            for field, field_warnings in action.get('warnings', {}).items():
                for entry in field_warnings:
                    for msg in entry.get('msg', []):
                        warnings.append(f"Action {action_id} - {field}: {msg}")

        if errors:
            error_msg = "Validation failed:\n" + "\n".join(errors)
            if warnings:
                error_msg += "\nWarnings:\n" + "\n".join(warnings)
            return (False, False, error_msg)

        if warnings:
            warning_msg = "Change set validated with warnings:\n" + "\n".join(warnings)
            return (True, False, warning_msg)

        return (True, False, "Change set validated correctly")

    def validate(self, changeset_id: str) -> Tuple[bool, bool, str]:
        """
        Validate a changeset without executing it.

        Args:
            changeset_id: ID of changeset to validate

        Returns:
            Tuple of (success, changed, message)
        """
        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/{changeset_id}/validate/"

            response = self.session.put(
                url,
                json={},
                headers=self._headers,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            return self._parse_validation_response(data)

        except ValueError as e:
            return (False, False, str(e))
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}")
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}")

    def validate_json(self, file_path: str) -> Tuple[bool, bool, str]:
        """
        Validate a changeset from a JSON file.

        Args:
            file_path: Path to JSON file containing changeset

        Returns:
            Tuple of (success, changed, message)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except FileNotFoundError:
            return (False, False, f"JSON file not found: {file_path}")
        except IOError as e:
            return (False, False, f"Error reading file: {str(e)}")

        try:
            changeset_data = json.loads(file_content)
        except json.JSONDecodeError as e:
            return (False, False, f"Invalid JSON in file: {str(e)}")

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/validate_json/"

            response = self.session.post(
                url,
                json=changeset_data,
                headers=self._headers,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            return self._parse_validation_response(data)

        except ValueError as e:
            return (False, False, str(e))
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}")
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}")

    def execute(self, changeset_id: str) -> Tuple[bool, bool, str]:
        """
        Validate and execute a changeset.

        Args:
            changeset_id: ID of changeset to execute

        Returns:
            Tuple of (success, changed, message)
        """
        # Validate first
        (completed, _, msg) = self.validate(changeset_id)
        if not completed:
            return (completed, False, msg)

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/{changeset_id}/execute/"

            response = self.session.put(
                url,
                json={},
                headers=self._headers,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            return self._parse_execute_response(data)

        except ValueError as e:
            return (False, False, str(e))
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}")
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}")

    def execute_json(self, file_path: str) -> Tuple[bool, bool, str]:
        """
        Execute a changeset from a JSON file.

        Args:
            file_path: Path to JSON file containing changeset

        Returns:
            Tuple of (success, changed, message)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except FileNotFoundError:
            return (False, False, f"JSON file not found: {file_path}")
        except IOError as e:
            return (False, False, f"Error reading file: {str(e)}")

        try:
            changeset_data = json.loads(file_content)
        except json.JSONDecodeError as e:
            return (False, False, f"Invalid JSON in file: {str(e)}")

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/execute_json/"

            response = self.session.post(
                url,
                json=changeset_data,
                headers=self._headers,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            return self._parse_execute_response(data)

        except ValueError as e:
            return (False, False, str(e))
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}")
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}")

    def validate_yaml(self, file_path: str) -> Tuple[bool, bool, str]:
        """
        Validate a changeset from a YAML file.

        Args:
            file_path: Path to YAML file containing changeset

        Returns:
            Tuple of (success, changed, message)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except FileNotFoundError:
            return (False, False, f"YAML file not found: {file_path}")
        except IOError as e:
            return (False, False, f"Error reading file: {str(e)}")

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/validate_yaml/"

            response = self.session.post(
                url,
                data=file_content,
                headers=self._yaml_headers,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            return self._parse_validation_response(data)

        except ValueError as e:
            return (False, False, str(e))
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}")
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}")

    def execute_yaml(self, file_path: str) -> Tuple[bool, bool, str]:
        """
        Execute a changeset from a YAML file.

        Args:
            file_path: Path to YAML file containing changeset

        Returns:
            Tuple of (success, changed, message)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except FileNotFoundError:
            return (False, False, f"YAML file not found: {file_path}")
        except IOError as e:
            return (False, False, f"Error reading file: {str(e)}")

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/execute_yaml/"

            response = self.session.post(
                url,
                data=file_content,
                headers=self._yaml_headers,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            return self._parse_execute_response(data)

        except ValueError as e:
            return (False, False, str(e))
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}")
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}")

    @staticmethod
    def _parse_execute_response(api_response: Dict[str, Any]) -> Tuple[bool, bool, str]:
        """
        Parse changeset execution response.

        Args:
            api_response: API response dictionary

        Returns:
            Tuple of (success, changed, message)
        """
        try:
            success = api_response.get('data', {}).get('attributes', {}).get('successful')

            if success is True:
                return (True, True, "Change Set was executed successfully")
            elif success is False:
                description = api_response.get('data', {}).get('attributes', {}).get(
                    'description', 'Unknown error'
                )
                msg = f"Change Set execution was not successful. {description}"
                return (False, False, msg)
            else:
                return (True, False, "Change Set is still running, results to be emailed")

        except (KeyError, TypeError) as e:
            return (False, False, f"Failed to parse execution response: {str(e)}")

    def close(self) -> None:
        """Close the session."""
        self.session.close()


def validate_arguments(module: AnsibleModule) -> None:
    """
    Validate module arguments based on selected action.

    Args:
        module: Ansible module instance

    Raises:
        Raises module.fail_json if validation fails
    """
    action = module.params.get('action')
    changeset_id = module.params.get('changeset_id')
    file_path = module.params.get('file_path')

    if action in ['validate', 'execute'] and not changeset_id:
        module.fail_json(
            msg=f"'changeset_id' is required when action is '{action}'"
        )

    if action in ['validate_json', 'execute_json', 'validate_yaml', 'execute_yaml'] and not file_path:
        module.fail_json(
            msg=f"'file_path' is required when action is '{action}'"
        )


def main() -> None:
    """Main Ansible module entry point."""
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True, type='str'),
            action=dict(
                required=True,
                type='str',
                choices=['validate', 'execute', 'validate_json', 'execute_json', 'validate_yaml', 'execute_yaml']
            ),
            api_key=dict(required=True, type='str', no_log=True),
            changeset_id=dict(required=False, type='str'),
            file_path=dict(required=False, type='str'),
            ssl=dict(required=False, type='bool', default=True),
            timeout=dict(required=False, type='int', default=30),
            validate_certs=dict(required=False, type='bool', default=True)
        ),
        supports_check_mode=False,
        required_together=[]
    )

    # Validate arguments
    validate_arguments(module)

    # Create client
    client = InProdAPIClient(
        hostname=module.params['host'],
        api_key=module.params['api_key'],
        ssl=module.params.get('ssl', True),
        timeout=module.params.get('timeout', 30),
        validate_certs=module.params.get('validate_certs', True)
    )

    try:
        action = module.params['action']

        if action == 'validate':
            return_status, changed, msg = client.validate(
                module.params['changeset_id']
            )
        elif action == 'execute':
            return_status, changed, msg = client.execute(
                module.params['changeset_id']
            )
        elif action == 'validate_json':
            return_status, changed, msg = client.validate_json(
                module.params['file_path']
            )
        elif action == 'execute_json':
            return_status, changed, msg = client.execute_json(
                module.params['file_path']
            )
        elif action == 'validate_yaml':
            return_status, changed, msg = client.validate_yaml(
                module.params['file_path']
            )
        elif action == 'execute_yaml':
            return_status, changed, msg = client.execute_yaml(
                module.params['file_path']
            )

        if return_status:
            module.exit_json(changed=changed, msg=msg)
        else:
            module.fail_json(changed=changed, msg=msg)

    finally:
        client.close()


if __name__ == '__main__':
    main()
