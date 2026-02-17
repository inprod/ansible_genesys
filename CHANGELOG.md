# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-02-17

### Changed
- All validate and execute operations now run as background tasks with automatic polling for results
- Replaced synchronous response parsing with task-based polling via `GET /api/v1/task-status/{task_id}/`

### Added
- New `environment` parameter to override the target environment for a changeset
- Accepts environment ID (integer) or environment name (string, case insensitive)
- Takes precedence over the environment field defined in the changeset payload
- Useful for CI/CD workflows where the same changeset is promoted through environments (e.g., dev, staging, production)
- New `poll_interval` parameter to control seconds between task status polls (default: 5)
- New `max_poll_time` parameter to set maximum wait time for task completion (default: 600 seconds)
- `_extract_task_id()` method for extracting task IDs from API responses
- `_poll_task()` method for polling the task status endpoint
- `_handle_task_result()` method for coordinating polling and result parsing
- `_parse_task_validation_result()` for parsing async validation results
- `_parse_task_execute_result()` for parsing async execution results

### Removed
- `_parse_validation_response()` — replaced by `_parse_task_validation_result()`
- `_parse_execute_response()` — replaced by `_parse_task_execute_result()`

## [2.0.0] - 2026-02-13

### Changed
- **BREAKING**: Replaced `username`/`password` authentication with `api_key` authentication
- **BREAKING**: Converted to modern Ansible collection structure
- **BREAKING**: Migrated from low-level `http.client` to `requests` library for HTTP operations
- API requests now use `Api-Key` header instead of token-based authentication
- Removed the `authenticate()` method and `/api/v1/admin/obtain-auth-token/` login flow
- Updated to require Python 3.8+ (dropped Python 2.7 support)
- Module now accessed as `inprod.genesys.inprod` instead of standalone module

### Added
- New `validate_json` action to validate changesets from a JSON file without executing
- New `validate_yaml` action to validate changesets from a YAML file without executing
- New `execute_yaml` action to execute changesets from a YAML file
- New `timeout` parameter for HTTP request timeouts (default: 30 seconds)
- New `validate_certs` parameter for SSL certificate validation control
- Comprehensive argument validation for required parameters based on action
- `InProdAPIClient` class for cleaner API operations
- Unit tests in `tests/unit/plugins/modules/`
- Integration tests in `tests/integration/targets/`
- `galaxy.yml` for Ansible Galaxy distribution
- `requirements.txt` for Python dependencies management
- Proper Ansible collection structure with `plugins/modules/` directory
- Enhanced error handling with specific exception types
- Session management with automatic connection cleanup

### Removed
- `username` parameter (use `api_key` instead)
- `password` parameter (use `api_key` instead)

### Fixed
- Removed bare `except:` clauses - now using specific exception handling
- Improved error message extraction from API responses
- Better handling of malformed JSON responses
- Session persistence across multiple API calls

### Security
- SSL certificate validation is now configurable (enabled by default)
- Improved password handling with proper no_log enforcement
- Better connection error handling and reporting

## [1.0.0] - Initial Release

### Added
- Initial release of InProd Ansible module
- Support for validate, execute, and execute_json actions
- Basic authentication with username/password
- HTTP and HTTPS support
