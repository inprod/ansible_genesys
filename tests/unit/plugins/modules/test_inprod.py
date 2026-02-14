#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit tests for inprod module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from ansible.module_utils.basic import AnsibleModule


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


class TestInProdAPIClient:
    """Tests for InProdAPIClient class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock requests session."""
        return Mock()

    @patch('changeset.requests.Session')
    def test_client_initialization(self, mock_session_class):
        """Test client initialization."""
        from changeset import InProdAPIClient

        mock_session_class.return_value = Mock()

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='a1b2c3d4e5f6a7b8',
            ssl=True,
            timeout=45,
            validate_certs=False
        )

        assert client.hostname == 'test.example.com'
        assert client.api_key == 'a1b2c3d4e5f6a7b8'
        assert client.ssl is True
        assert client.timeout == 45
        assert client.validate_certs is False

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


class TestValidationResponseParsing:
    """Tests for _parse_validation_response."""

    def test_validation_success_empty_errors(self):
        """Test successful validation with no errors or warnings."""
        from changeset import InProdAPIClient

        data = [
            {
                'action_id': 6,
                'change_set_id': 6,
                'errors': {},
                'warnings': {}
            }
        ]

        success, changed, msg = InProdAPIClient._parse_validation_response(data)
        assert success is True
        assert changed is False
        assert msg == "Change set validated correctly"

    def test_validation_failure_with_errors(self):
        """Test validation failure when errors are present in payload."""
        from changeset import InProdAPIClient

        data = [
            {
                'action_id': 6,
                'change_set_id': 6,
                'errors': {
                    'name': [{'iteration': None, 'msg': ['name needs to be unique']}]
                },
                'warnings': {}
            }
        ]

        success, changed, msg = InProdAPIClient._parse_validation_response(data)
        assert success is False
        assert changed is False
        assert 'Validation failed' in msg
        assert 'name needs to be unique' in msg
        assert 'Action 6' in msg

    def test_validation_failure_multiple_errors(self):
        """Test validation failure with multiple error fields."""
        from changeset import InProdAPIClient

        data = [
            {
                'action_id': 6,
                'change_set_id': 6,
                'errors': {
                    'name': [{'iteration': None, 'msg': ['name needs to be unique']}],
                    'division': [{'iteration': None, 'msg': ['division is required']}]
                },
                'warnings': {}
            }
        ]

        success, changed, msg = InProdAPIClient._parse_validation_response(data)
        assert success is False
        assert 'name needs to be unique' in msg
        assert 'division is required' in msg

    def test_validation_success_with_warnings(self):
        """Test validation succeeds but reports warnings."""
        from changeset import InProdAPIClient

        data = [
            {
                'action_id': 6,
                'change_set_id': 6,
                'errors': {},
                'warnings': {
                    'description': [{'iteration': None, 'msg': ['description is empty']}]
                }
            }
        ]

        success, changed, msg = InProdAPIClient._parse_validation_response(data)
        assert success is True
        assert changed is False
        assert 'warnings' in msg.lower()
        assert 'description is empty' in msg

    def test_validation_failure_with_errors_and_warnings(self):
        """Test validation failure includes both errors and warnings."""
        from changeset import InProdAPIClient

        data = [
            {
                'action_id': 6,
                'change_set_id': 6,
                'errors': {
                    'name': [{'iteration': None, 'msg': ['name needs to be unique']}]
                },
                'warnings': {
                    'description': [{'iteration': None, 'msg': ['description is empty']}]
                }
            }
        ]

        success, changed, msg = InProdAPIClient._parse_validation_response(data)
        assert success is False
        assert 'name needs to be unique' in msg
        assert 'description is empty' in msg

    def test_validation_non_list_response(self):
        """Test validation with unexpected non-list response treats as success."""
        from changeset import InProdAPIClient

        data = {'status': 'ok'}

        success, changed, msg = InProdAPIClient._parse_validation_response(data)
        assert success is True
        assert msg == "Change set validated correctly"


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
        assert headers['Content-Type'] == 'application/x-yaml'
        assert headers['Authorization'] == 'Api-Key testkey123'


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

        success, changed, msg = client.validate_yaml('/nonexistent/file.yml')
        assert success is False
        assert changed is False
        assert 'YAML file not found' in msg

    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_validate_yaml_sends_raw_content(self, mock_open, mock_session_class):
        """Test validate_yaml sends raw YAML content."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test Queue\ntype: queue\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {'action_id': 1, 'change_set_id': 1, 'errors': {}, 'warnings': {}}
        ]
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            ssl=True
        )

        success, changed, msg = client.validate_yaml('/path/to/file.yml')
        assert success is True
        assert msg == "Change set validated correctly"

        # Verify raw YAML was sent (data= not json=)
        call_args = mock_session.post.call_args
        assert call_args.kwargs.get('data') == yaml_content or call_args[1].get('data') == yaml_content
        assert 'application/x-yaml' in str(call_args)

    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_validate_yaml_with_validation_errors(self, mock_open, mock_session_class):
        """Test validate_yaml reports validation errors from response payload."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = [
            {
                'action_id': 1,
                'change_set_id': 1,
                'errors': {
                    'name': [{'iteration': None, 'msg': ['name needs to be unique']}]
                },
                'warnings': {}
            }
        ]
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        success, changed, msg = client.validate_yaml('/path/to/file.yml')
        assert success is False
        assert 'name needs to be unique' in msg


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

        success, changed, msg = client.execute_yaml('/nonexistent/file.yml')
        assert success is False
        assert changed is False
        assert 'YAML file not found' in msg

    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_execute_yaml_success(self, mock_open, mock_session_class):
        """Test execute_yaml with successful execution."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test Queue\ntype: queue\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'attributes': {
                    'successful': True
                }
            }
        }
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123',
            ssl=True
        )

        success, changed, msg = client.execute_yaml('/path/to/file.yml')
        assert success is True
        assert changed is True
        assert msg == "Change Set was executed successfully"

        # Verify raw YAML was sent
        call_args = mock_session.post.call_args
        assert call_args.kwargs.get('data') == yaml_content or call_args[1].get('data') == yaml_content

    @patch('changeset.requests.Session')
    @patch('builtins.open', create=True)
    def test_execute_yaml_failure(self, mock_open, mock_session_class):
        """Test execute_yaml with failed execution."""
        from changeset import InProdAPIClient

        yaml_content = "name: Test\n"
        mock_open.return_value.__enter__ = Mock(return_value=Mock(read=Mock(return_value=yaml_content)))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'attributes': {
                    'successful': False,
                    'description': 'Queue already exists'
                }
            }
        }
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = InProdAPIClient(
            hostname='test.example.com',
            api_key='testkey123'
        )

        success, changed, msg = client.execute_yaml('/path/to/file.yml')
        assert success is False
        assert changed is False
        assert 'Queue already exists' in msg
