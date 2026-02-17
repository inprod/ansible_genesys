#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import time
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
    poll_interval:
        description:
            - Seconds to wait between task status polling requests
            - All operations run as background tasks and require polling for results
        type: int
        default: 5
    max_poll_time:
        description:
            - Maximum seconds to wait for a background task to complete
            - If the task has not completed within this time, the module will fail
        type: int
        default: 600
    environment:
        description:
            - Override the target environment for the changeset
            - Accepts the environment ID (integer) or environment name (string, case insensitive)
            - Takes precedence over the environment field defined in the changeset payload
            - Useful for CI/CD workflows where the same changeset is promoted through environments
        type: raw
        required: false

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

- name: Execute changeset from JSON file with environment override (by ID)
  inprod.genesys_cloud.changeset:
    host: 'your-company.inprod.io'
    action: 'execute_json'
    api_key: '{{ vault_inprod_api_key }}'
    file_path: '/path/to/execute.json'
    environment: 3
    ssl: true

- name: Execute changeset from YAML file with environment override (by name)
  inprod.genesys_cloud.changeset:
    host: 'your-company.inprod.io'
    action: 'execute_yaml'
    api_key: '{{ vault_inprod_api_key }}'
    file_path: '/path/to/changeset.yml'
    environment: 'Production'
    ssl: true
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
run_id:
    description: The run ID from the execution, useful for retrieving the run report
    type: int
    returned: when action is execute, execute_json, or execute_yaml
    sample: 24
changeset_name:
    description: The name of the changeset that was validated or executed
    type: str
    returned: on successful task completion
    sample: "Deploy Queue Config"
environment:
    description: The target environment the changeset was run against
    type: dict
    returned: on successful task completion
    sample: {"id": 3, "name": "Production"}
'''


class InProdAPIClient:
    """Client for InProd API operations."""

    def __init__(
        self,
        hostname: str,
        api_key: str,
        ssl: bool = True,
        timeout: int = 30,
        validate_certs: bool = True,
        poll_interval: int = 5,
        max_poll_time: int = 600,
        environment=None
    ):
        """
        Initialize InProd API client.

        Args:
            hostname: InProd service hostname
            api_key: API key for authentication
            ssl: Use HTTPS if True
            timeout: Request timeout in seconds
            validate_certs: Validate SSL certificates if True
            poll_interval: Seconds between task status polls
            max_poll_time: Maximum seconds to wait for task completion
            environment: Environment ID (int) or name (str) to override the changeset target
        """
        self.hostname = hostname
        self.api_key = api_key
        self.ssl = ssl
        self.timeout = timeout
        self.validate_certs = validate_certs
        self.poll_interval = poll_interval
        self.max_poll_time = max_poll_time
        self.environment = environment
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
    def _params(self) -> Dict[str, Any]:
        """Build query parameters for API requests."""
        params = {}
        if self.environment is not None:
            params['environment'] = self.environment
        return params

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
            'Content-Type': 'application/yaml'
        }

    @staticmethod
    def _extract_task_id(response_data: Dict[str, Any]) -> str:
        """
        Extract task_id from the initial API response.

        Args:
            response_data: Parsed JSON response from the API

        Returns:
            The task ID string

        Raises:
            ValueError: If task_id is not found in the response
        """
        try:
            task_id = response_data['data']['attributes']['task_id']
        except (KeyError, TypeError):
            raise ValueError(
                "API response did not contain a task_id. "
                f"Response: {json.dumps(response_data)}"
            )
        if not task_id:
            raise ValueError("API returned an empty task_id")
        return task_id

    def _poll_task(self, task_id: str) -> Tuple[str, Any]:
        """
        Poll the task status endpoint until the task reaches a terminal state.

        Args:
            task_id: The task ID to poll

        Returns:
            Tuple of (status, result_or_error) where result_or_error is the
            result dict on SUCCESS or error string on FAILURE/REVOKED

        Raises:
            ValueError: If polling times out or encounters an unexpected error
        """
        url = f"{self.base_url}/api/v1/task-status/{task_id}/"
        terminal_statuses = {'SUCCESS', 'FAILURE', 'REVOKED'}
        elapsed = 0

        while elapsed < self.max_poll_time:
            time.sleep(self.poll_interval)
            elapsed += self.poll_interval

            response = self.session.get(
                url,
                headers=self._headers,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            status = data.get('status')

            if status in terminal_statuses:
                if status == 'SUCCESS':
                    return (status, data.get('result') or {})
                elif status == 'FAILURE':
                    return (status, data.get('error') or 'Unknown error')
                else:  # REVOKED
                    return (status, 'Task was cancelled')

        raise ValueError(
            f"Task {task_id} did not complete within {self.max_poll_time} seconds"
        )

    def _handle_task_result(
        self, task_id: str, parse_result
    ) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Poll for task completion and parse the result.

        Args:
            task_id: The task ID to poll
            parse_result: Callable that parses the SUCCESS result dict
                          into (success, changed, message, result_data)

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        status, result = self._poll_task(task_id)

        if status == 'SUCCESS':
            return parse_result(result)
        elif status == 'FAILURE':
            return (False, False, f"Task failed: {result}", {})
        else:  # REVOKED
            return (False, False, f"Task was cancelled: {result}", {})

    @staticmethod
    def _parse_task_validation_result(
        result: Dict[str, Any]
    ) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Parse validation result from a completed background task.

        Args:
            result: The result dict from a SUCCESS task status response

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        result_data = {
            'changeset_name': result.get('changeset_name'),
            'environment': result.get('environment'),
        }

        is_valid = result.get('is_valid', False)

        if is_valid:
            return (True, False, "Change set validated correctly", result_data)

        errors = []
        warnings = []

        for action in result.get('validation_results', []):
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
            return (False, False, error_msg, result_data)

        if warnings:
            warning_msg = "Change set validated with warnings:\n" + "\n".join(warnings)
            return (True, False, warning_msg, result_data)

        return (False, False, "Validation failed with unknown errors", result_data)

    @staticmethod
    def _parse_task_execute_result(
        result: Dict[str, Any]
    ) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Parse execution result from a completed background task.

        Args:
            result: The result dict from a SUCCESS task status response

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        result_data = {
            'run_id': result.get('run_id'),
            'changeset_name': result.get('changeset_name'),
            'environment': result.get('environment'),
        }
        successful = result.get('successful')
        run_id = result.get('run_id')

        if successful is True:
            msg = f"Change Set was executed successfully (run_id: {run_id})"
            return (True, True, msg, result_data)
        else:
            msg = f"Change Set execution was not successful (run_id: {run_id})"
            return (False, False, msg, result_data)

    def validate(self, changeset_id: str) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Validate a changeset without executing it.

        Submits the validation as a background task, then polls for completion.

        Args:
            changeset_id: ID of changeset to validate

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/{changeset_id}/validate/"

            response = self.session.put(
                url,
                json={},
                headers=self._headers,
                params=self._params,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            task_id = self._extract_task_id(data)
            return self._handle_task_result(
                task_id, self._parse_task_validation_result
            )

        except ValueError as e:
            return (False, False, str(e), {})
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}", {})
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}", {})

    def validate_json(self, file_path: str) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Validate a changeset from a JSON file.

        Submits the validation as a background task, then polls for completion.

        Args:
            file_path: Path to JSON file containing changeset

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except FileNotFoundError:
            return (False, False, f"JSON file not found: {file_path}", {})
        except IOError as e:
            return (False, False, f"Error reading file: {str(e)}", {})

        try:
            changeset_data = json.loads(file_content)
        except json.JSONDecodeError as e:
            return (False, False, f"Invalid JSON in file: {str(e)}", {})

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/validate_json/"

            response = self.session.post(
                url,
                json=changeset_data,
                headers=self._headers,
                params=self._params,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            task_id = self._extract_task_id(data)
            return self._handle_task_result(
                task_id, self._parse_task_validation_result
            )

        except ValueError as e:
            return (False, False, str(e), {})
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}", {})
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}", {})

    def execute(self, changeset_id: str) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Validate and execute a changeset.

        Validates first by submitting a background task and polling for the
        result. If validation passes, submits the execution as a background
        task and polls for completion.

        Args:
            changeset_id: ID of changeset to execute

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        # Validate first
        (completed, _, msg, _) = self.validate(changeset_id)
        if not completed:
            return (completed, False, msg, {})

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/{changeset_id}/execute/"

            response = self.session.put(
                url,
                json={},
                headers=self._headers,
                params=self._params,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            task_id = self._extract_task_id(data)
            return self._handle_task_result(
                task_id, self._parse_task_execute_result
            )

        except ValueError as e:
            return (False, False, str(e), {})
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}", {})
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}", {})

    def execute_json(self, file_path: str) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Execute a changeset from a JSON file.

        Submits the execution as a background task, then polls for completion.

        Args:
            file_path: Path to JSON file containing changeset

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except FileNotFoundError:
            return (False, False, f"JSON file not found: {file_path}", {})
        except IOError as e:
            return (False, False, f"Error reading file: {str(e)}", {})

        try:
            changeset_data = json.loads(file_content)
        except json.JSONDecodeError as e:
            return (False, False, f"Invalid JSON in file: {str(e)}", {})

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/execute_json/"

            response = self.session.post(
                url,
                json=changeset_data,
                headers=self._headers,
                params=self._params,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            task_id = self._extract_task_id(data)
            return self._handle_task_result(
                task_id, self._parse_task_execute_result
            )

        except ValueError as e:
            return (False, False, str(e), {})
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}", {})
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}", {})

    def validate_yaml(self, file_path: str) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Validate a changeset from a YAML file.

        Submits the validation as a background task, then polls for completion.

        Args:
            file_path: Path to YAML file containing changeset

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except FileNotFoundError:
            return (False, False, f"YAML file not found: {file_path}", {})
        except IOError as e:
            return (False, False, f"Error reading file: {str(e)}", {})

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/validate_yaml/"

            response = self.session.post(
                url,
                data=file_content,
                headers=self._yaml_headers,
                params=self._params,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            task_id = self._extract_task_id(data)
            return self._handle_task_result(
                task_id, self._parse_task_validation_result
            )

        except ValueError as e:
            return (False, False, str(e), {})
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}", {})
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}", {})

    def execute_yaml(self, file_path: str) -> Tuple[bool, bool, str, Dict[str, Any]]:
        """
        Execute a changeset from a YAML file.

        Submits the execution as a background task, then polls for completion.

        Args:
            file_path: Path to YAML file containing changeset

        Returns:
            Tuple of (success, changed, message, result_data)
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except FileNotFoundError:
            return (False, False, f"YAML file not found: {file_path}", {})
        except IOError as e:
            return (False, False, f"Error reading file: {str(e)}", {})

        try:
            url = f"{self.base_url}/api/v1/change-set/change-set/execute_yaml/"

            response = self.session.post(
                url,
                data=file_content,
                headers=self._yaml_headers,
                params=self._params,
                timeout=self.timeout
            )

            data = self._handle_response(response)
            task_id = self._extract_task_id(data)
            return self._handle_task_result(
                task_id, self._parse_task_execute_result
            )

        except ValueError as e:
            return (False, False, str(e), {})
        except (ConnectionError, Timeout) as e:
            return (False, False, f"Connection error: {str(e)}", {})
        except RequestException as e:
            return (False, False, f"Request error: {str(e)}", {})

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
            validate_certs=dict(required=False, type='bool', default=True),
            poll_interval=dict(required=False, type='int', default=5),
            max_poll_time=dict(required=False, type='int', default=600),
            environment=dict(required=False, type='raw', default=None)
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
        validate_certs=module.params.get('validate_certs', True),
        poll_interval=module.params.get('poll_interval', 5),
        max_poll_time=module.params.get('max_poll_time', 600),
        environment=module.params.get('environment')
    )

    try:
        action = module.params['action']

        if action == 'validate':
            return_status, changed, msg, result_data = client.validate(
                module.params['changeset_id']
            )
        elif action == 'execute':
            return_status, changed, msg, result_data = client.execute(
                module.params['changeset_id']
            )
        elif action == 'validate_json':
            return_status, changed, msg, result_data = client.validate_json(
                module.params['file_path']
            )
        elif action == 'execute_json':
            return_status, changed, msg, result_data = client.execute_json(
                module.params['file_path']
            )
        elif action == 'validate_yaml':
            return_status, changed, msg, result_data = client.validate_yaml(
                module.params['file_path']
            )
        elif action == 'execute_yaml':
            return_status, changed, msg, result_data = client.execute_yaml(
                module.params['file_path']
            )

        # Filter out None values from result_data
        extra = {k: v for k, v in result_data.items() if v is not None}

        if return_status:
            module.exit_json(changed=changed, msg=msg, **extra)
        else:
            module.fail_json(changed=changed, msg=msg, **extra)

    finally:
        client.close()


if __name__ == '__main__':
    main()
