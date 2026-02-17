#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit tests for inprod module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from ansible.module_utils.basic import AnsibleModule


# ---------------------------------------------------------------------------
# Helper: build a task-id API response (returned by validate/execute endpoints)
# ---------------------------------------------------------------------------

def _task_response(task_id='test-task-id-123'):
    """Build a mock initial API response containing a task_id."""
    return {
        'data': {
            'type': 'change-set-validation',
            'attributes': {
                'title': 'Processing',
                'description': 'Running as background task.',
                'task_id': task_id
            }
        }
    }


def _poll_success(result):
    """Build a mock SUCCESS polling response."""
    return {'task_id': 'test-task-id-123', 'status': 'SUCCESS', 'result': result}


def _poll_failure(error='Something went wrong'):
    """Build a mock FAILURE polling response."""
    return {'task_id': 'test-task-id-123', 'status': 'FAILURE', 'error': error}


def _poll_pending():
    """Build a mock PENDING polling response."""
    return {'task_id': 'test-task-id-123', 'status': 'PENDING'}


def _poll_started():
    """Build a mock STARTED polling response."""
    return {'task_id': 'test-task-id-123', 'status': 'STARTED'}


def _validation_result_valid():
    """Build a valid validation task result."""
    return {
        'is_valid': True,
        'validation_results': [],
        'changeset_name': 'Test Changeset',
        'environment': {'id': 1, 'name': 'Dev'}
    }


def _validation_result_invalid():
    """Build an invalid validation task result with errors."""
    return {
        'is_valid': False,
        'validation_results': [
            {
                'action_id': 534,
                'errors': {
                    'name': [{'iteration': None, 'msg': ['name needs to be unique']}]
                },
                'warnings': {}
            }
        ],
        'changeset_name': 'Test Changeset',
        'environment': {'id': 1, 'name': 'Dev'}
    }


def _execution_result_success():
    """Build a successful execution task result."""
    return {
        'run_id': 24,
        'successful': True,
        'changeset_name': 'Test Changeset',
        'environment': {'id': 1, 'name': 'Dev'}
    }


def _execution_result_failure():
    """Build a failed execution task result."""
    return {
        'run_id': 24,
        'successful': False,
        'changeset_name': 'Test Changeset',
        'environment': {'id': 1, 'name': 'Dev'}
    }


# ---------------------------------------------------------------------------
# Argument validation tests (unchanged)
# ---------------------------------------------------------------------------

def test_validate_arguments_missing_changeset_id():
    """Test that validate_arguments raises error for missing changeset_id."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'validate',
        'changeset_id': None,
        'file_path': None
    }
    module.fail_json = Mock(side_effect=SystemExit)

    with pytest.raises(SystemExit):
        validate_arguments(module)

    module.fail_json.assert_called_once()
    call_args = module.fail_json.call_args
    assert 'changeset_id' in str(call_args)


def test_validate_arguments_execute_missing_changeset_id():
    """Test that validate_arguments raises error for execute without changeset_id."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'execute',
        'changeset_id': None,
        'file_path': None
    }
    module.fail_json = Mock(side_effect=SystemExit)

    with pytest.raises(SystemExit):
        validate_arguments(module)

    module.fail_json.assert_called_once()


def test_validate_arguments_execute_json_missing_file_path():
    """Test that validate_arguments raises error for execute_json without file_path."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'execute_json',
        'changeset_id': None,
        'file_path': None
    }
    module.fail_json = Mock(side_effect=SystemExit)

    with pytest.raises(SystemExit):
        validate_arguments(module)

    module.fail_json.assert_called_once()


def test_validate_arguments_valid_validate():
    """Test that validate_arguments passes for valid validate action."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'validate',
        'changeset_id': '123',
        'file_path': None
    }
    module.fail_json = Mock()

    validate_arguments(module)

    module.fail_json.assert_not_called()


def test_validate_arguments_valid_execute_json():
    """Test that validate_arguments passes for valid execute_json action."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'execute_json',
        'changeset_id': None,
        'file_path': '/path/to/file.json'
    }
    module.fail_json = Mock()

    validate_arguments(module)

    module.fail_json.assert_not_called()


def test_validate_arguments_validate_json_missing_file_path():
    """Test that validate_arguments raises error for validate_json without file_path."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'validate_json',
        'changeset_id': None,
        'file_path': None
    }
    module.fail_json = Mock(side_effect=SystemExit)

    with pytest.raises(SystemExit):
        validate_arguments(module)

    module.fail_json.assert_called_once()


def test_validate_arguments_valid_validate_json():
    """Test that validate_arguments passes for valid validate_json action."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'validate_json',
        'changeset_id': None,
        'file_path': '/path/to/file.json'
    }
    module.fail_json = Mock()

    validate_arguments(module)

    module.fail_json.assert_not_called()


def test_validate_arguments_validate_yaml_missing_file_path():
    """Test that validate_arguments raises error for validate_yaml without file_path."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'validate_yaml',
        'changeset_id': None,
        'file_path': None
    }
    module.fail_json = Mock(side_effect=SystemExit)

    with pytest.raises(SystemExit):
        validate_arguments(module)

    module.fail_json.assert_called_once()


def test_validate_arguments_valid_validate_yaml():
    """Test that validate_arguments passes for valid validate_yaml action."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'validate_yaml',
        'changeset_id': None,
        'file_path': '/path/to/file.yml'
    }
    module.fail_json = Mock()

    validate_arguments(module)

    module.fail_json.assert_not_called()


def test_validate_arguments_execute_yaml_missing_file_path():
    """Test that validate_arguments raises error for execute_yaml without file_path."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'execute_yaml',
        'changeset_id': None,
        'file_path': None
    }
    module.fail_json = Mock(side_effect=SystemExit)

    with pytest.raises(SystemExit):
        validate_arguments(module)

    module.fail_json.assert_called_once()


def test_validate_arguments_valid_execute_yaml():
    """Test that validate_arguments passes for valid execute_yaml action."""
    from changeset import validate_arguments

    module = Mock(spec=AnsibleModule)
    module.params = {
        'action': 'execute_yaml',
        'changeset_id': None,
        'file_path': '/path/to/file.yml'
    }
    module.fail_json = Mock()

    validate_arguments(module)

    module.fail_json.assert_not_called()


# ---------------------------------------------------------------------------
# Client initialization tests
# ---------------------------------------------------------------------------

class TestInProdAPIClient:
    """Tests for InProdAPIClient class."""

    @patch('changeset.requests.Session')
    def test_client_initialization(self, mock_session_class):
        """Test client initialization with all parameters."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='a1b2c3d4e5f6a7b8',
            ssl=True,
            timeout=45,
            validate_certs=False,
            poll_interval=10,
            max_poll_time=300
        )

        assert client.hostname == 'test.example.com'
        assert client.api_key == 'a1b2c3d4e5f6a7b8'
        assert client.ssl is True
        assert client.timeout == 45
        assert client.validate_certs is False
        assert client.poll_interval == 10
        assert client.max_poll_time == 300

    @patch('changeset.requests.Session')
    def test_client_default_poll_params(self, mock_session_class):
        """Test client uses default polling parameters."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        assert client.poll_interval == 5
        assert client.max_poll_time == 600

    @patch('changeset.requests.Session')
    def test_base_url_http(self, mock_session_class):
        """Test base_url property with HTTP."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            ssl=False
        )

        assert client.base_url == 'http://test.example.com'

    @patch('changeset.requests.Session')
    def test_base_url_https(self, mock_session_class):
        """Test base_url property with HTTPS."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            ssl=True
        )

        assert client.base_url == 'https://test.example.com'

    @patch('changeset.requests.Session')
    def test_client_environment_stored(self, mock_session_class):
        """Test client stores environment parameter."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            environment=3
        )

        assert client.environment == 3

    @patch('changeset.requests.Session')
    def test_client_environment_string(self, mock_session_class):
        """Test client stores string environment parameter."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            environment='Production'
        )

        assert client.environment == 'Production'

    @patch('changeset.requests.Session')
    def test_client_environment_default_none(self, mock_session_class):
        """Test client environment defaults to None."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        assert client.environment is None

    @patch('changeset.requests.Session')
    def test_params_with_environment(self, mock_session_class):
        """Test _params includes environment when set."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            environment=3
        )

        assert client._params == {'environment': 3}

    @patch('changeset.requests.Session')
    def test_params_with_environment_string(self, mock_session_class):
        """Test _params includes string environment when set."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            environment='Production'
        )

        assert client._params == {'environment': 'Production'}

    @patch('changeset.requests.Session')
    def test_params_without_environment(self, mock_session_class):
        """Test _params is empty when environment not set."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        assert client._params == {}

    @patch('changeset.requests.Session')
    def test_extract_errors_list_response(self, mock_session_class):
        """Test _extract_errors with list response."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        response = [
            {
                'action_id': 1,
                'errors': {'field1': ['error1', 'error2']}
            }
        ]

        result = client._extract_errors(response)
        assert 'Action Id: 1' in result
        assert 'field1' in result

    @patch('changeset.requests.Session')
    def test_extract_errors_dict_response(self, mock_session_class):
        """Test _extract_errors with dict response."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        response = {
            'errors': {
                'base': ['Change set no longer exists']
            }
        }

        result = client._extract_errors(response)
        assert 'base' in result
        assert 'Change set no longer exists' in result


# ---------------------------------------------------------------------------
# Task ID extraction tests
# ---------------------------------------------------------------------------

class TestExtractTaskId:
    """Tests for _extract_task_id."""

    def test_extract_task_id_success(self):
        """Test successful task_id extraction."""
        from changeset import InProdAPIClient

        data = _task_response('abc-123')
        task_id = InProdAPIClient._extract_task_id(data)
        assert task_id == 'abc-123'

    def test_extract_task_id_missing(self):
        """Test ValueError when task_id is missing."""
        from changeset import InProdAPIClient

        data = {'data': {'attributes': {}}}
        with pytest.raises(ValueError, match='task_id'):
            InProdAPIClient._extract_task_id(data)

    def test_extract_task_id_empty(self):
        """Test ValueError when task_id is empty string."""
        from changeset import InProdAPIClient

        data = _task_response('')
        with pytest.raises(ValueError, match='empty task_id'):
            InProdAPIClient._extract_task_id(data)

    def test_extract_task_id_malformed_response(self):
        """Test ValueError with completely malformed response."""
        from changeset import InProdAPIClient

        with pytest.raises(ValueError, match='task_id'):
            InProdAPIClient._extract_task_id({'unexpected': 'format'})


# ---------------------------------------------------------------------------
# Task polling tests
# ---------------------------------------------------------------------------

class TestPollTask:
    """Tests for _poll_task method."""

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_poll_task_success_first_attempt(self, mock_session_class, mock_sleep):
        """Test polling returns SUCCESS on first poll."""
        from changeset import InProdAPIClient

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = _poll_success(_validation_result_valid())
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        status, result = client._poll_task('task-123')
        assert status == 'SUCCESS'
        assert result['is_valid'] is True
        mock_sleep.assert_called_once_with(1)

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_poll_task_pending_then_success(self, mock_session_class, mock_sleep):
        """Test polling handles PENDING then SUCCESS."""
        from changeset import InProdAPIClient

        mock_session = Mock()
        pending_response = Mock()
        pending_response.status_code = 200
        pending_response.json.return_value = _poll_pending()

        success_response = Mock()
        success_response.status_code = 200
        success_response.json.return_value = _poll_success(_execution_result_success())

        mock_session.get.side_effect = [pending_response, success_response]
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        status, result = client._poll_task('task-123')
        assert status == 'SUCCESS'
        assert result['successful'] is True
        assert mock_sleep.call_count == 2

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_poll_task_pending_started_success(self, mock_session_class, mock_sleep):
        """Test polling handles PENDING -> STARTED -> SUCCESS."""
        from changeset import InProdAPIClient

        mock_session = Mock()
        responses = [
            Mock(status_code=200, json=Mock(return_value=_poll_pending())),
            Mock(status_code=200, json=Mock(return_value=_poll_started())),
            Mock(status_code=200, json=Mock(return_value=_poll_success(_validation_result_valid())))
        ]
        mock_session.get.side_effect = responses
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        status, result = client._poll_task('task-123')
        assert status == 'SUCCESS'
        assert mock_sleep.call_count == 3

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_poll_task_failure(self, mock_session_class, mock_sleep):
        """Test polling returns FAILURE."""
        from changeset import InProdAPIClient

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = _poll_failure('Database connection failed')
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        status, result = client._poll_task('task-123')
        assert status == 'FAILURE'
        assert result == 'Database connection failed'

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_poll_task_revoked(self, mock_session_class, mock_sleep):
        """Test polling returns REVOKED."""
        from changeset import InProdAPIClient

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'task_id': 'task-123', 'status': 'REVOKED'
        }
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        status, result = client._poll_task('task-123')
        assert status == 'REVOKED'
        assert 'cancelled' in result

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_poll_task_timeout(self, mock_session_class, mock_sleep):
        """Test polling raises ValueError on timeout."""
        from changeset import InProdAPIClient

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = _poll_pending()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=2,
            max_poll_time=5
        )

        with pytest.raises(ValueError, match='did not complete'):
            client._poll_task('task-123')


# ---------------------------------------------------------------------------
# Validation result parsing tests
# ---------------------------------------------------------------------------

class TestParseTaskValidationResult:
    """Tests for _parse_task_validation_result."""

    def test_valid_changeset(self):
        """Test parsing a valid changeset result."""
        from changeset import InProdAPIClient

        success, changed, msg, result_data = InProdAPIClient._parse_task_validation_result(
            _validation_result_valid()
        )
        assert success is True
        assert changed is False
        assert msg == "Change set validated correctly"
        assert result_data['changeset_name'] == 'Test Changeset'
        assert result_data['environment'] == {'id': 1, 'name': 'Dev'}

    def test_invalid_changeset_with_errors(self):
        """Test parsing an invalid changeset result with errors."""
        from changeset import InProdAPIClient

        success, changed, msg, result_data = InProdAPIClient._parse_task_validation_result(
            _validation_result_invalid()
        )
        assert success is False
        assert changed is False
        assert 'Validation failed' in msg
        assert 'name needs to be unique' in msg
        assert 'Action 534' in msg

    def test_invalid_with_multiple_errors(self):
        """Test validation failure with multiple error fields."""
        from changeset import InProdAPIClient

        result = {
            'is_valid': False,
            'validation_results': [
                {
                    'action_id': 6,
                    'errors': {
                        'name': [{'iteration': None, 'msg': ['name needs to be unique']}],
                        'division': [{'iteration': None, 'msg': ['division is required']}]
                    },
                    'warnings': {}
                }
            ]
        }

        success, changed, msg, result_data = InProdAPIClient._parse_task_validation_result(result)
        assert success is False
        assert 'name needs to be unique' in msg
        assert 'division is required' in msg

    def test_valid_with_warnings(self):
        """Test validation succeeds with warnings."""
        from changeset import InProdAPIClient

        result = {
            'is_valid': True,
            'validation_results': [],
        }

        success, changed, msg, result_data = InProdAPIClient._parse_task_validation_result(result)
        assert success is True
        assert changed is False

    def test_invalid_with_errors_and_warnings(self):
        """Test validation failure includes both errors and warnings."""
        from changeset import InProdAPIClient

        result = {
            'is_valid': False,
            'validation_results': [
                {
                    'action_id': 6,
                    'errors': {
                        'name': [{'iteration': None, 'msg': ['name needs to be unique']}]
                    },
                    'warnings': {
                        'description': [{'iteration': None, 'msg': ['description is empty']}]
                    }
                }
            ]
        }

        success, changed, msg, result_data = InProdAPIClient._parse_task_validation_result(result)
        assert success is False
        assert 'name needs to be unique' in msg
        assert 'description is empty' in msg

    def test_invalid_no_details(self):
        """Test invalid with no validation_results returns unknown error."""
        from changeset import InProdAPIClient

        result = {'is_valid': False, 'validation_results': []}

        success, changed, msg, result_data = InProdAPIClient._parse_task_validation_result(result)
        assert success is False
        assert 'unknown errors' in msg.lower()


# ---------------------------------------------------------------------------
# Execution result parsing tests
# ---------------------------------------------------------------------------

class TestParseTaskExecuteResult:
    """Tests for _parse_task_execute_result."""

    def test_successful_execution(self):
        """Test parsing a successful execution result."""
        from changeset import InProdAPIClient

        success, changed, msg, result_data = InProdAPIClient._parse_task_execute_result(
            _execution_result_success()
        )
        assert success is True
        assert changed is True
        assert 'run_id: 24' in msg
        assert result_data['run_id'] == 24
        assert result_data['changeset_name'] == 'Test Changeset'
        assert result_data['environment'] == {'id': 1, 'name': 'Dev'}

    def test_failed_execution(self):
        """Test parsing a failed execution result includes run_id."""
        from changeset import InProdAPIClient

        success, changed, msg, result_data = InProdAPIClient._parse_task_execute_result(
            _execution_result_failure()
        )
        assert success is False
        assert changed is False
        assert 'not successful' in msg
        assert 'run_id: 24' in msg
        assert result_data['run_id'] == 24
        assert result_data['changeset_name'] == 'Test Changeset'


# ---------------------------------------------------------------------------
# YAML headers tests
# ---------------------------------------------------------------------------

class TestYAMLHeaders:
    """Tests for YAML headers property."""

    @patch('changeset.requests.Session')
    def test_yaml_headers_content_type(self, mock_session_class):
        """Test that _yaml_headers sets correct content type."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        headers = client._yaml_headers
        assert headers['Content-Type'] == 'application/yaml'
        assert headers['Authorization'] == 'Api-Key testkey123'


# ---------------------------------------------------------------------------
# Validate with polling (end-to-end)
# ---------------------------------------------------------------------------

class TestValidateWithPolling:
    """End-to-end tests for validate actions with task polling."""

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_validate_success(self, mock_session_class, mock_sleep):
        """Test validate action with successful polling result."""
        from changeset import InProdAPIClient

        mock_session = Mock()

        # Initial PUT returns task_id
        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('task-abc')
        mock_session.put.return_value = initial_response

        # Poll returns SUCCESS
        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_validation_result_valid())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.validate('125')
        assert success is True
        assert changed is False
        assert msg == "Change set validated correctly"

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_validate_failure(self, mock_session_class, mock_sleep):
        """Test validate action with validation errors."""
        from changeset import InProdAPIClient

        mock_session = Mock()

        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('task-abc')
        mock_session.put.return_value = initial_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_validation_result_invalid())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.validate('125')
        assert success is False
        assert 'name needs to be unique' in msg

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_validate_passes_environment_param(self, mock_session_class, mock_sleep):
        """Test validate action sends environment as query parameter."""
        from changeset import InProdAPIClient

        mock_session = Mock()

        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('task-abc')
        mock_session.put.return_value = initial_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_validation_result_valid())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60,
            environment=3
        )

        success, changed, msg, result_data = client.validate('125')
        assert success is True

        # Verify environment was passed as query parameter
        call_args = mock_session.put.call_args
        params = call_args.kwargs.get('params') or call_args[1].get('params', {})
        assert params.get('environment') == 3

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_validate_no_environment_param(self, mock_session_class, mock_sleep):
        """Test validate action sends empty params when no environment set."""
        from changeset import InProdAPIClient

        mock_session = Mock()

        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('task-abc')
        mock_session.put.return_value = initial_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_validation_result_valid())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.validate('125')
        assert success is True

        # Verify params is empty dict (no environment)
        call_args = mock_session.put.call_args
        params = call_args.kwargs.get('params') or call_args[1].get('params', {})
        assert 'environment' not in params

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_validate_task_failure(self, mock_session_class, mock_sleep):
        """Test validate action when the background task itself fails."""
        from changeset import InProdAPIClient

        mock_session = Mock()

        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('task-abc')
        mock_session.put.return_value = initial_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_failure('Internal error')
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.validate('125')
        assert success is False
        assert 'Task failed' in msg
        assert 'Internal error' in msg


# ---------------------------------------------------------------------------
# Execute with polling (end-to-end)
# ---------------------------------------------------------------------------

class TestExecuteWithPolling:
    """End-to-end tests for execute action with task polling."""

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_execute_success(self, mock_session_class, mock_sleep):
        """Test execute action: validate passes then execute succeeds."""
        from changeset import InProdAPIClient

        mock_session = Mock()

        # Both validate and execute use PUT
        validate_response = Mock()
        validate_response.status_code = 200
        validate_response.json.return_value = _task_response('validate-task')

        execute_response = Mock()
        execute_response.status_code = 200
        execute_response.json.return_value = _task_response('execute-task')

        mock_session.put.side_effect = [validate_response, execute_response]

        # Polling: first call is for validate task, second for execute task
        validate_poll = Mock()
        validate_poll.status_code = 200
        validate_poll.json.return_value = _poll_success(_validation_result_valid())

        execute_poll = Mock()
        execute_poll.status_code = 200
        execute_poll.json.return_value = _poll_success(_execution_result_success())

        mock_session.get.side_effect = [validate_poll, execute_poll]
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.execute('125')
        assert success is True
        assert changed is True
        assert 'executed successfully' in msg
        assert result_data['run_id'] == 24

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_execute_validation_fails(self, mock_session_class, mock_sleep):
        """Test execute action: stops when validation fails."""
        from changeset import InProdAPIClient

        mock_session = Mock()

        validate_response = Mock()
        validate_response.status_code = 200
        validate_response.json.return_value = _task_response('validate-task')
        mock_session.put.return_value = validate_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_validation_result_invalid())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.execute('125')
        assert success is False
        assert changed is False
        assert 'name needs to be unique' in msg

        # Verify only one PUT was made (validate only, no execute)
        assert mock_session.put.call_count == 1

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    def test_execute_execution_fails(self, mock_session_class, mock_sleep):
        """Test execute action: validation passes but execution fails."""
        from changeset import InProdAPIClient

        mock_session = Mock()

        validate_response = Mock()
        validate_response.status_code = 200
        validate_response.json.return_value = _task_response('validate-task')

        execute_response = Mock()
        execute_response.status_code = 200
        execute_response.json.return_value = _task_response('execute-task')

        mock_session.put.side_effect = [validate_response, execute_response]

        validate_poll = Mock()
        validate_poll.status_code = 200
        validate_poll.json.return_value = _poll_success(_validation_result_valid())

        execute_poll = Mock()
        execute_poll.status_code = 200
        execute_poll.json.return_value = _poll_success(_execution_result_failure())

        mock_session.get.side_effect = [validate_poll, execute_poll]
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.execute('125')
        assert success is False
        assert changed is False
        assert 'not successful' in msg


# ---------------------------------------------------------------------------
# Validate YAML with polling
# ---------------------------------------------------------------------------

class TestValidateYAML:
    """Tests for validate_yaml method."""

    @patch('changeset.requests.Session')
    def test_validate_yaml_file_not_found(self, mock_session_class):
        """Test validate_yaml with missing file."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        success, changed, msg, result_data = client.validate_yaml('/nonexistent/file.yml')
        assert success is False
        assert changed is False
        assert 'YAML file not found' in msg

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_validate_yaml_sends_raw_content(self, mock_open, mock_session_class, mock_sleep):
        """Test validate_yaml sends raw YAML content and polls for result."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test Queue\ntype: queue\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()

        # Initial POST returns task_id
        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('yaml-task')
        mock_session.post.return_value = initial_response

        # Poll returns SUCCESS
        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_validation_result_valid())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            ssl=True,
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.validate_yaml('/path/to/file.yml')
        assert success is True
        assert msg == "Change set validated correctly"

        # Verify raw YAML was sent (data= not json=)
        call_args = mock_session.post.call_args
        assert call_args.kwargs.get('data') == yaml_content or call_args[1].get('data') == yaml_content
        assert 'application/yaml' in str(call_args)

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_validate_yaml_with_validation_errors(self, mock_open, mock_session_class, mock_sleep):
        """Test validate_yaml reports validation errors from polled result."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()

        initial_response = Mock()
        initial_response.status_code = 201
        initial_response.json.return_value = _task_response('yaml-task')
        mock_session.post.return_value = initial_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_validation_result_invalid())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.validate_yaml('/path/to/file.yml')
        assert success is False
        assert 'name needs to be unique' in msg


# ---------------------------------------------------------------------------
# Execute YAML with polling
# ---------------------------------------------------------------------------

class TestExecuteYAML:
    """Tests for execute_yaml method."""

    @patch('changeset.requests.Session')
    def test_execute_yaml_file_not_found(self, mock_session_class):
        """Test execute_yaml with missing file."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        success, changed, msg, result_data = client.execute_yaml('/nonexistent/file.yml')
        assert success is False
        assert changed is False
        assert 'YAML file not found' in msg

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_execute_yaml_success(self, mock_open, mock_session_class, mock_sleep):
        """Test execute_yaml with successful execution."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test Queue\ntype: queue\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()

        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('yaml-exec-task')
        mock_session.post.return_value = initial_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_execution_result_success())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            ssl=True,
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.execute_yaml('/path/to/file.yml')
        assert success is True
        assert changed is True
        assert 'executed successfully' in msg
        assert result_data['run_id'] == 24

        # Verify raw YAML was sent
        call_args = mock_session.post.call_args
        assert call_args.kwargs.get('data') == yaml_content or call_args[1].get('data') == yaml_content

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_execute_yaml_passes_environment_param(self, mock_open, mock_session_class, mock_sleep):
        """Test execute_yaml sends environment as query parameter."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test Queue\ntype: queue\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()

        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('yaml-exec-task')
        mock_session.post.return_value = initial_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_execution_result_success())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            ssl=True,
            poll_interval=1,
            max_poll_time=60,
            environment='Production'
        )

        success, changed, msg, result_data = client.execute_yaml('/path/to/file.yml')
        assert success is True

        # Verify environment was passed as query parameter
        call_args = mock_session.post.call_args
        params = call_args.kwargs.get('params') or call_args[1].get('params', {})
        assert params.get('environment') == 'Production'

    @patch('changeset.time.sleep')
    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_execute_yaml_failure(self, mock_open, mock_session_class, mock_sleep):
        """Test execute_yaml with failed execution."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()

        initial_response = Mock()
        initial_response.status_code = 200
        initial_response.json.return_value = _task_response('yaml-exec-task')
        mock_session.post.return_value = initial_response

        poll_response = Mock()
        poll_response.status_code = 200
        poll_response.json.return_value = _poll_success(_execution_result_failure())
        mock_session.get.return_value = poll_response

        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            poll_interval=1,
            max_poll_time=60
        )

        success, changed, msg, result_data = client.execute_yaml('/path/to/file.yml')
        assert success is False
        assert changed is False
        assert 'not successful' in msg
