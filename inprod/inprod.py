#!/usr/bin/python

import json, re, os
from ansible.module_utils.basic import *
try:
    import http.client as http
    from urllib.parse import urlparse
except:
    import httplib as http
    from urlparse import urlparse

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'InProd Solutions Pty Ltd'
}

DOCUMENTATION = '''
---
module: inprod
short_description: Use Ansible to call InProd Changesets
options:
    host:
     description:
        - The host name to access InProd
     required: True
    action:
     description:
        - The changeset action to perform (validate, execute, execute_json)
     required: True
    username:
     description:
        - Username to authenticate.
     required: True
    password
     description:
        - Password to authenticate.
     required: True
    changeset_id
     description:
        - change set id (Required in validate and execute actions).
     required: False
    file_path:
        - Absolute path of JSON file which is used in execute_json action
     required: False
requirements:
    - "python >= 2.7"
'''

EXAMPLES = '''
- hosts: localhost
  tasks:
  - name: validate the change set
    inprod:
     host: 'blue.inprod.cloud'
     action: 'validate'
     username: 'milos'
     password: 'xx'
     changeset_id: 125
  - name: execute a changeset based on its Id
    inprod:
     host: 'blue.inprod.cloud'
     action: 'execute'
     username: 'milos'
     password: 'xx'
     changeset_id: 125
  - name: execute a changeset stored as JSON file
    inprod:
     host: 'blue.inprod.cloud'
     action: 'execute_json'
     username: 'milos'
     password: 'xx'
     file_path: '/Your Directory Path/execute.json'
'''


def http_action(send_data, hostname, url_path, method="PUT", header=None, ssl=False):
    """ Responsible for sending all of the HTTP requests and dealing with
    any error responses """
    data_body = json.dumps(send_data).encode('utf-8')

    if ssl:
        conn = http.HTTPConnection(hostname, 443)
    else:
        conn = http.HTTPConnection(hostname, 80)

    conn.request(method, url_path, data_body, header)
    response = conn.getresponse()

    try:
        body = response.readlines()[0].decode("utf-8")
    except:
        body = response.read().decode("utf-8")

    if response.status != 200:
        try:
            error_msg = get_errors(json.loads(body))
        except:
            error_msg = body
        msg = "API responded with HTTP {} Error!\n{}".format(
            response.status,
            error_msg
            )
        raise ValueError(msg)

    return json.loads(body)


def get_errors(response_body_json):
    """ Extracts details from a standard Bow error message which includes
    validation errors"""

    result = []

    print("response_body_json: {}".format(response_body_json))

    if isinstance(response_body_json, list):
        for error in response_body_json:
            if 'action_id' in error:
                # this is a validation / changeset run response
                if not error.get('errors'):
                    # No errors to report
                    continue
                action_errors = [
                    "{}: {}".format(k, " - ".join(v))
                    for (k, v) in error.get('errors').items()
                    ]
                msg = "Action Id: {} {}".format(
                    error['action_id'],
                    " - ".join(action_errors)
                )
            else:
                # This is a JSON API error response
                msg = "{}: {}".format(
                    error.get('source', {}).get('pointer', 'base'),
                    error.get('detail')
                    )
            result.append(msg)

    elif isinstance(response_body_json['errors'], dict):
        # This is a regular error message
        # {'errors': {'base': ['Change set no longer exists']}}
        for (key, val) in response_body_json['errors'].items():
                msg = "{}: {}".format(
                    key,
                    " - ".join(val) if isinstance(val, list) else val
                    )
                result.append(msg)

    return " \n".join(result)


def get_token(username, password, hostname, ssl=False):
    """From the login action, extract out the authenticate token"""
    login_details = {'username': username, 'password': password}
    headers = {'Content-Type': 'application/json'}
    res = http_action(login_details, hostname, '/api/v1/admin/obtain-auth-token/', method="POST", header=headers)
    return res['tokens']['auth']


def validate(variables_json, hostname, changeset_id, headers):
    """ Perform validation of the changeset """
    api_path = "/api/v1/change-set/change-set/{}/validate/".format(changeset_id)
    try:
        api_response = http_action(variables_json, hostname, api_path, method='PUT', header=headers)
    except Exception as e:
        return (False, False, "{}".format(e))

    errors = get_errors(api_response)
    if errors:
        msg = "The changeset did not validate. \n{}".format(errors)
        return (False, False, msg)
    else:
        msg = "Change set validated correctly"
        return(True, False, msg)


def execute_response(api_response):
    """ determine the respose from an execute  """
    if api_response['data']['attributes']['successful'] is True:
        return (True, True, "Change Set was executed successfully")
    elif api_response['data']['attributes']['successful'] is False:
        msg = "Change Set execution was not successfully. {}".format(
            api_response['data']['attributes']['description']
            )
        return (False, False, msg)
    else:
        return (True, False, "Change Set is still running, results to be emailed")


def changeset_api(hostname, api_name, username, password, changeset_id, file_path=None):
    """ Main function that performs the work """

    if api_name not in ['validate', 'execute', 'execute_json']:
        return (False, False, "Action: '{}' is not supported".format(api_name))

    try:
        token = get_token(username, password, hostname)
    except Exception as e:
        return (False, False, "{}".format(e))

    headers = {'Authorization': "Token " + token, 'Content-Type': 'application/json'}
    variables_json = {}

    if api_name == 'validate':
        return validate(variables_json, hostname, changeset_id, headers)

    elif api_name == 'execute':
        # We validate the change set before running it
        (completed, changed, msg) = validate(variables_json, hostname, changeset_id, headers)
        if completed is False:
            return (completed, changed, msg)

        # Now the changeset validated we can run it
        api_path = "/api/v1/change-set/change-set/{}/execute/".format(changeset_id)
        try:
            api_response = http_action(variables_json, hostname, api_path, method='PUT', header=headers)
        except Exception as e:
            # 404 means no permission to perform this action
            return (False, False, "{}".format(e))

        return execute_response(api_response)

    elif api_name == 'execute_json':

        try:
            file_content = open(file_path, 'r').read()
        except FileNotFoundError:
            return (False, False, "JSON File can not be found!")

        api_path = "/api/v1/change-set/change-set/{}/".format(api_name)
        try:
            api_response = http_action(json.loads(file_content), hostname, api_path, method='POST', header=headers)
        except Exception as e:
            return (False, False, "{}".format(e))

        return execute_response(api_response)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(required=True),
            action=dict(required=True),
            username=dict(required=True),
            password=dict(required=True, no_log=True),
            changeset_id=dict(required=False),
            file_path=dict(required=False)
        )
    )
    return_status, changed, msg = changeset_api(
        hostname=module.params['host'],
        api_name=module.params['action'],
        username=module.params['username'],
        password=module.params['password'],
        changeset_id=module.params['changeset_id'],
        file_path=module.params['file_path']
        )

    if return_status:
        module.exit_json(changed=changed, msg=msg)
    else:
        module.fail_json(changed=changed, msg=msg)

if __name__ == '__main__':
    main()
