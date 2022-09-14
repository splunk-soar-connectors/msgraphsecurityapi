# File: microsoftgraphsecurityapi_connector.py
#
# Copyright (c) 2022 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import grp
import ipaddress
import json
import os
import pwd
import time
from datetime import datetime
from urllib.parse import urlencode

# SOAR App imports
import encryption_helper
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from django.http import HttpResponse
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from microsoftgraphsecurityapi_consts import *

MS_GRAPHSECURITYAPI_TC_FILE = 'oauth_task.out'


def _handle_login_redirect(request, key):
    """ This function is used to redirect login request to microsoft login page.

    :param request: Data given to REST endpoint
    :param key: Key to search in state file
    :return: response authorization_url
    """

    asset_id = request.GET.get('asset_id')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL')
    state = _load_app_state(asset_id)
    url = state.get(key)
    if not url:
        return HttpResponse('App state is invalid, {key} not found.'.format(key=key))
    response = HttpResponse(status=302)
    response['Location'] = url
    return response


def _load_app_state(asset_id, app_connector=None):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: state: Current state file as a dictionary
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    dirpath = os.path.dirname(os.path.abspath(__file__))
    state_file = '{0}/{1}_state.json'.format(dirpath, asset_id)
    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == dirpath:
        if app_connector:
            app_connector.debug_print('In _load_app_state: Invalid asset_id')
        return {}

    state = {}
    try:
        with open(real_state_file_path, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)
    except Exception as e:
        if app_connector:
            error_txt = _get_error_message_from_exception(e)
            app_connector.debug_print('In _load_app_state: {0}'.format(error_txt))

    if app_connector:
        app_connector.debug_print('Loaded state: ', state)

    try:
        state = _decrypt_state(state, asset_id)
    except Exception as e:
        if app_connector:
            app_connector.debug_print("{}: {}".format(MS_GRAPHSECURITYAPI_DECRYPTION_ERROR, str(e)))
        state = {}

    return state


def _save_app_state(state, asset_id, app_connector):
    """ This functions is used to save current state in file.

    :param state: Dictionary which contains data to write in state file
    :param asset_id: asset_id
    :param app_connector: Object of app_connector class
    :return: status: phantom.APP_SUCCESS
    """

    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    dirpath = os.path.dirname(os.path.abspath(__file__))
    state_file = '{0}/{1}_state.json'.format(dirpath, asset_id)

    real_state_file_path = os.path.abspath(state_file)
    if not os.path.dirname(real_state_file_path) == dirpath:
        if app_connector:
            app_connector.debug_print('In _save_app_state: Invalid asset_id')
        return {}

    try:
        state = _encrypt_state(state, asset_id)
    except Exception as e:
        if app_connector:
            app_connector.debug_print("{}: {}".format(MS_GRAPHSECURITYAPI_ENCRYPTION_ERROR, str(e)))
        return phantom.APP_ERROR

    if app_connector:
        app_connector.debug_print('Saving state: ', state)

    try:
        with open(real_state_file_path, 'w+') as state_file_obj:
            state_file_obj.write(json.dumps(state))
    except Exception as e:
        error_txt = _get_error_message_from_exception(e)
        msg = 'Unable to save state file: {0}'.format(str(error_txt))
        if app_connector:
            app_connector.debug_print(msg)
        print(msg)
        return phantom.APP_ERROR

    return phantom.APP_SUCCESS


def _get_error_message_from_exception(e):
    """
    Get appropriate error message from the exception.
    :param e: Exception object
    :return: error message
    """
    error_code = None
    error_msg = MS_GRAPHSECURITYAPI_ERROR_MSG_UNKNOWN

    try:
        if hasattr(e, "args"):
            if len(e.args) > 1:
                error_code = e.args[0]
                error_msg = e.args[1]
            elif len(e.args) == 1:
                error_msg = e.args[0]
    except Exception:
        pass

    if not error_code:
        error_text = "Error Message: {}".format(error_msg)
    else:
        error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

    return error_text


def _handle_login_response(request):
    """ This function is used to get the login response of authorization request from microsoft login page.

    :param request: Data given to REST endpoint
    :return: HttpResponse. The response displayed on authorization URL page
    """

    asset_id = request.GET.get('state')
    if not asset_id:
        return HttpResponse('ERROR: Asset ID not found in URL\n{}'.format(json.dumps(request.GET)))

    # Check for error in URL
    error = request.GET.get('error')
    error_description = request.GET.get('error_description')

    # If there is an error in response
    if error:
        message = 'Error: {0}'.format(error)
        if error_description:
            message = '{0} Details: {1}'.format(message, error_description)
        return HttpResponse('Server returned {0}'.format(message))

    code = request.GET.get('code')

    # If code is unavailable
    if not code:
        return HttpResponse('Error while authenticating\n{0}'.format(json.dumps(request.GET)))

    state = _load_app_state(asset_id)
    state['code'] = code
    _save_app_state(state, asset_id, None)

    return HttpResponse('Code received. Please close this window, the action will continue to get new token.', content_type="text/plain")


def _handle_rest_request(request, path_parts):
    """ Handle requests for authorization.

    :param request: Data given to REST endpoint
    :param path_parts: parts of the URL passed
    :return: dictionary containing response parameters
    """

    if len(path_parts) < 2:
        return HttpResponse('error: True, message: Invalid REST endpoint request')

    call_type = path_parts[1]

    # To handle authorize request in test connectivity action
    if call_type == 'start_oauth':
        return _handle_login_redirect(request, 'authorization_url')

    # To handle response from microsoft login page
    if call_type == 'result':
        return_val = _handle_login_response(request)
        asset_id = request.GET.get('state')
        if asset_id:
            app_dir = os.path.dirname(os.path.abspath(__file__))
            auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, asset_id, MS_GRAPHSECURITYAPI_TC_FILE)
            open(auth_status_file_path, 'w').close()
            try:
                uid = pwd.getpwnam('apache').pw_uid
                gid = grp.getgrnam('phantom').gr_gid
                os.chown(auth_status_file_path, uid, gid)
                os.chmod(auth_status_file_path, '0664')
            except Exception:
                pass

        return return_val
    return HttpResponse('error: Invalid endpoint')


def _get_dir_name_from_app_name(app_name):
    """ Get name of the directory for the app.

    :param app_name: Name of the application for which directory name is required
    :return: app_name: Name of the directory for the application
    """

    app_name = ''.join([x for x in app_name if x.isalnum()])
    app_name = app_name.lower()
    if not app_name:
        app_name = 'app_for_phantom'
    return app_name


def _decrypt_state(state, salt):
    """
    Decrypts the state.

    :param state: state dictionary
    :param salt: salt used for decryption
    :return: decrypted state
    """
    if not state.get("is_encrypted"):
        return state

    access_token = state.get("token", {}).get("access_token")
    if access_token:
        state["token"]["access_token"] = encryption_helper.decrypt(access_token, salt)

    refresh_token = state.get("token", {}).get("refresh_token")
    if refresh_token:
        state["token"]["refresh_token"] = encryption_helper.decrypt(refresh_token, salt)

    code = state.get("code")
    if code:
        state["code"] = encryption_helper.decrypt(code, salt)

    return state


def _encrypt_state(state, salt):
    """
    Encrypts the state.

    :param state: state dictionary
    :param salt: salt used for encryption
    :return: encrypted state
    """

    access_token = state.get("token", {}).get("access_token")
    if access_token:
        state["token"]["access_token"] = encryption_helper.encrypt(access_token, salt)

    refresh_token = state.get("token", {}).get("refresh_token")
    if refresh_token:
        state["token"]["refresh_token"] = encryption_helper.encrypt(refresh_token, salt)

    code = state.get("code")
    if code:
        state["code"] = encryption_helper.encrypt(code, salt)

    state["is_encrypted"] = True

    return state


class RetVal(tuple):

    def __new__(cls, val1, val2):

        return tuple.__new__(RetVal, (val1, val2))


class MicrosoftSecurityAPIConnector(BaseConnector):

    def __init__(self):

        super(MicrosoftSecurityAPIConnector, self).__init__()

        self._state = None
        self._tenant = None
        self._client_id = None
        self._client_secret = None
        self._access_token = None
        self._refresh_token = None

    def load_state(self):
        """
        Load the contents of the state file to the state dictionary and decrypt it.

        :return: loaded state
        """
        state = super().load_state()
        try:
            state = _decrypt_state(state, self.get_asset_id())
        except Exception as e:
            self.debug_print("{}: {}".format(MS_GRAPHSECURITYAPI_DECRYPTION_ERROR, str(e)))
            state = None

        return state

    def save_state(self, state):
        """
        Encrypt and save the current state dictionary to the the state file.

        :param state: state dictionary
        :return: status
        """
        try:
            state = _encrypt_state(state, self.get_asset_id())
        except Exception as e:
            self.debug_print("{}: {}".format(MS_GRAPHSECURITYAPI_ENCRYPTION_ERROR, str(e)))
            return phantom.APP_ERROR

        return super().save_state(state)

    def _process_empty_reponse(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if 200 <= response.status_code <= 299:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            error_txt = _get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(error_txt)), None)

        # Please specify the status codes here
        if 200 <= response.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     response.text.replace('{', '{{')
                                                                                     .replace('}', '}}'))

        # Show only error message if available
        if isinstance(resp_json.get('error', {}), dict) and resp_json.get('error', {}).get('message'):
            message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                         resp_json['error']['message'])

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        if 'text/javascript' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response,
            action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_reponse(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _update_request(self, action_result, endpoint, headers=None, params=None, data=None, method='get'):
        """ This function is used to update the headers with access_token before making REST call.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        # In pagination, URL of next page contains complete URL
        # So no need to modify them
        if not endpoint.startswith(MS_GRAPHSECURITYAPI_BASE_URL):
            endpoint = '{0}{1}'.format(MS_GRAPHSECURITYAPI_BASE_URL, endpoint)

        if headers is None:
            headers = {}

        token_data = {
            'client_id': self._client_id,
            'scope': MS_GRAPHSECURITYAPI_REST_REQUEST_SCOPE,
            'client_secret': self._client_secret,
            'grant_type': MS_GRAPHSECURITYAPI_JSON_REFRESH_TOKEN,
            'refresh_token': self._refresh_token
        }

        if not self._access_token:
            if not self._refresh_token:
                # If none of the access_token and refresh_token is available
                return action_result.set_status(phantom.APP_ERROR, status_message=MS_GRAPHSECURITYAPI_TOKEN_NOT_AVAILABLE_MSG), None

            # If refresh_token is available and access_token is not available, generate new access_token
            status = self._generate_new_access_token(action_result=action_result, data=token_data)

            if phantom.is_fail(status):
                return action_result.get_status(), None

        headers.update({'Authorization': 'Bearer {0}'.format(self._access_token),
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'})

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=endpoint, headers=headers,
                                                  params=params, data=data, method=method)

        # If token is expired, generate new token
        if MS_GRAPHSECURITYAPI_TOKEN_EXPIRED_MSG in action_result.get_message():
            status = self._generate_new_access_token(action_result=action_result, data=token_data)

            if phantom.is_fail(status):
                return action_result.get_status(), None

            headers.update({'Authorization': 'Bearer {0}'.format(self._access_token)})

            ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=endpoint, headers=headers,
                                                      params=params, data=data, method=method)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return phantom.APP_SUCCESS, resp_json

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get", verify=True):
        """ Function that makes the REST call to the app.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE/PATCH (Default will be GET)
        :param verify: verify server certificate (Default True)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        try:
            timeout = MS_GRAPHSECURITYAPI_DEFAULT_REQUEST_TIMEOUT
            r = request_func(endpoint, data=data, headers=headers, verify=verify, params=params, timeout=timeout)
        except Exception as e:
            error_txt = _get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}"
                                                   .format(error_txt)), resp_json)
        return self._process_response(r, action_result)

    def _get_asset_name(self, action_result):
        """ Get name of the asset using Phantom URL.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message), asset name
        """

        asset_id = self.get_asset_id()
        rest_endpoint = MS_GRAPHSECURITYAPI_ASSET_INFO_URL.format(asset_id=asset_id)
        base_url = self.get_phantom_base_url()
        url = '{}{}{}'.format(base_url if base_url.endswith('/') else base_url + '/', 'rest', rest_endpoint)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)

        if phantom.is_fail(ret_val):
            return ret_val, None

        asset_name = resp_json.get('name')
        if not asset_name:
            return action_result.set_status(phantom.APP_ERROR, 'Asset Name for id: {0} not found.'.format(asset_id),
                                            None)
        return phantom.APP_SUCCESS, asset_name

    def _get_phantom_base_url_ms(self, action_result):
        """ Get base url of phantom.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        base url of phantom
        """

        base_url = self.get_phantom_base_url()
        url = '{}{}{}'.format(base_url if base_url.endswith('/') else base_url + '/', 'rest', MS_GRAPHSECURITYAPI_SYS_INFO_URL)
        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=url, verify=False)
        if phantom.is_fail(ret_val):
            return ret_val, None

        phantom_base_url = resp_json.get('base_url')

        if not phantom_base_url:
            return action_result.set_status(phantom.APP_ERROR, MS_GRAPHSECURITYAPI_BASE_URL_NOT_FOUND_MSG), None
        return phantom.APP_SUCCESS, phantom_base_url.rstrip('/')

    def _get_app_rest_url(self, action_result):
        """ Get URL for making rest calls.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        URL to make rest calls
        """

        ret_val, phantom_base_url = self._get_phantom_base_url_ms(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        ret_val, asset_name = self._get_asset_name(action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        self.save_progress('Using Phantom base URL as: {0}'.format(phantom_base_url))
        app_json = self.get_app_json()
        app_name = app_json['name']

        app_dir_name = _get_dir_name_from_app_name(app_name)
        url_to_app_rest = '{0}/rest/handler/{1}_{2}/{3}'.format(phantom_base_url, app_dir_name, app_json['appid'],
                                                                asset_name)
        return phantom.APP_SUCCESS, url_to_app_rest

    def _generate_new_access_token(self, action_result, data):
        """ This function is used to generate new access token using the code obtained on authorization.

        :param action_result: object of ActionResult class
        :param data: Data to send in REST call
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS
        """
        req_url = '{}{}'.format(MS_GRAPHSECURITYAPI_LOGIN_BASE_URL, MS_GRAPHSECURITYAPI_SERVER_TOKEN_URL.format(tenant_id=self._tenant))

        ret_val, resp_json = self._make_rest_call(action_result=action_result, endpoint=req_url,
                                                  data=urlencode(data), method="post")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._state[MS_GRAPHSECURITYAPI_JSON_TOKEN] = resp_json
        self._access_token = resp_json[MS_GRAPHSECURITYAPI_JSON_ACCESS_TOKEN]
        self._refresh_token = resp_json[MS_GRAPHSECURITYAPI_JSON_REFRESH_TOKEN]

        # Save state
        self.save_state(self._state)

        # Scenario -
        # The newely generated token is not being saved to state file and
        # automatic workflow for token has been stopped.
        # So we have to check that token from response and
        # token which are saved to state file after successful generation of new token are same or not.
        self._state = self.load_state()
        if self._access_token != self._state.get('token', {}).get('access_token'):
            return action_result.set_status(phantom.APP_ERROR, MS_GRAPHSECURITYAPI_INVALID_PERMRISSION_ERROR)

        return phantom.APP_SUCCESS

    def _create_alert_artifacts(self, alerts):

        artifacts = []
        for alert in alerts:
            alert_artifact = {}
            alert_artifact['label'] = 'alert'
            alert_artifact['name'] = 'alert Artifact'
            alert_artifact['cef_types'] = {'id': [alert['id']]}
            alert_artifact['source_data_identifier'] = alert.get('id')
            alert_artifact['data'] = alert
            alert_artifact['cef'] = alert
            alert_artifact["run_automation"] = True
            # Append to the artifacts list
            artifacts.append(alert_artifact)

        return artifacts

    def _handle_test_connectivity(self, param):
        """ Testing of given credentials and obtaining authorization for all other actions.

        :param param: (not used in this method)
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress(MS_GRAPHSECURITYAPI_MAKING_CONNECTION_MSG)

        # Get initial REST URL
        ret_val, app_rest_url = self._get_app_rest_url(action_result)
        if phantom.is_fail(ret_val):
            self.save_progress(MS_GRAPHSECURITYAPI_REST_URL_NOT_AVAILABLE_MSG.format(error=action_result.get_message()))
            return action_result.set_status(phantom.APP_ERROR, status_message=MS_GRAPHSECURITYAPI_TEST_CONNECTIVITY_FAILED_MSG)

        # Append /result to create redirect_uri
        redirect_uri = '{0}/result'.format(app_rest_url)
        self._state['redirect_uri'] = redirect_uri

        self.save_progress(MS_GRAPHSECURITYAPI_OAUTH_URL_MSG)
        self.save_progress(redirect_uri)

        # Authorization URL used to make request for getting code which is used to generate access token
        authorization_url = MS_GRAPHSECURITYAPI_AUTHORIZE_URL.format(tenant_id=self._tenant, client_id=self._client_id,
                                                         redirect_uri=redirect_uri, state=self.get_asset_id(),
                                                         response_type='code',
                                                         scope=MS_GRAPHSECURITYAPI_REST_REQUEST_SCOPE, resp_mode='query')
        authorization_url = '{}{}'.format(MS_GRAPHSECURITYAPI_LOGIN_BASE_URL, authorization_url)

        self._state['authorization_url'] = authorization_url

        # URL which would be shown to the user
        url_for_authorize_request = '{0}/start_oauth?asset_id={1}&'.format(app_rest_url, self.get_asset_id())
        _save_app_state(self._state, self.get_asset_id(), self)

        self.save_progress(MS_GRAPHSECURITYAPI_AUTHORIZE_USER_MSG)
        self.save_progress(url_for_authorize_request)

        time.sleep(MS_GRAPHSECURITYAPI_AUTHORIZE_WAIT_TIME)

        # Wait for some while user login to Microsoft
        status = self._wait(action_result=action_result)

        if phantom.is_fail(status):
            self.save_progress(MS_GRAPHSECURITYAPI_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        # Empty message to override last message of waiting
        self.send_progress('')
        self.save_progress(MS_GRAPHSECURITYAPI_CODE_RECEIVED_MSG)
        self._state = _load_app_state(self.get_asset_id(), self)

        # if code is not available in the state file
        if not self._state or not self._state.get('code'):
            return action_result.set_status(phantom.APP_ERROR, status_message=MS_GRAPHSECURITYAPI_TEST_CONNECTIVITY_FAILED_MSG)

        current_code = self._state['code']

        self.save_progress(MS_GRAPHSECURITYAPI_GENERATING_ACCESS_TOKEN_MSG)

        data = {
            'client_id': self._client_id,
            'scope': MS_GRAPHSECURITYAPI_REST_REQUEST_SCOPE,
            'client_secret': self._client_secret,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'code': current_code
        }
        # for first time access, new access token is generated
        ret_val = self._generate_new_access_token(action_result=action_result, data=data)

        if phantom.is_fail(ret_val):
            self.save_progress(MS_GRAPHSECURITYAPI_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(MS_GRAPHSECURITYAPI_CURRENT_USER_INFO_MSG)

        url = '{}{}'.format(MS_GRAPHSECURITYAPI_BASE_URL, MS_GRAPHSECURITYAPI_SELF_ENDPOINT)
        ret_val, _ = self._update_request(action_result=action_result, endpoint=url)

        if phantom.is_fail(ret_val):
            self.save_progress(MS_GRAPHSECURITYAPI_TEST_CONNECTIVITY_FAILED_MSG)
            return action_result.get_status()

        self.save_progress(MS_GRAPHSECURITYAPI_GOT_CURRENT_USER_INFO_MSG)
        self.save_progress(MS_GRAPHSECURITYAPI_TEST_CONNECTIVITY_PASSED_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _wait(self, action_result):
        """ This function is used to hold the action till user login.

        :param action_result: Object of ActionResult class
        :return: status (success/failed)
        """

        app_dir = os.path.dirname(os.path.abspath(__file__))
        # file to check whether the request has been granted or not
        auth_status_file_path = '{0}/{1}_{2}'.format(app_dir, self.get_asset_id(), MS_GRAPHSECURITYAPI_TC_FILE)
        time_out = False
        self.save_progress('Waiting for Autorization Code to complete')
        # wait-time while request is being granted
        for i in range(40):
            self._state = _load_app_state(self.get_asset_id(), self)
            self.send_progress('{0}'.format('.' * (i % 10)))
            if os.path.isfile(auth_status_file_path):
                time_out = True
                os.unlink(auth_status_file_path)
                break
            time.sleep(MS_GRAPHSECURITYAPI_TC_STATUS_SLEEP)

        if not time_out:
            return action_result.set_status(phantom.APP_ERROR, status_message='Timeout. Please try again later.')
        self.send_progress('Authenticated')
        return phantom.APP_SUCCESS

    def convert_paramter_to_list(self, param):
        """
        Convert comma separated parameter string to list
        Args:
            param: Comma separated string

        Returns:
            list: tags
        """
        tags = param.split(",")
        tags = [tag.strip().replace('\"', "").replace("\'", "") for tag in tags]
        return list(filter(None, tags))

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address
        try:
            ipaddress.ip_address(str(ip_address_input))
        except Exception:
            return False
        return True

    def _paginator(self, action_result, endpoint, params=None, query=None, limit=None):
        """
        This action is used to create an iterator that will paginate through responses from called methods.

        :param action_result: Object of ActionResult class
        :param endpoint: Endpoint for pagination
        :param params: Request parameters
        :param params: Filter string
        :param limit: limit for number of alerts
        """

        list_items = []

        if query:
            params = {"$filter": query}

        while True:
            ret_val, response = self._update_request(action_result, endpoint, params=params)
            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            res_val = response.get("value")
            if res_val:
                list_items.extend(res_val)

            if limit and len(list_items) >= limit:
                list_items = list_items[:limit]
                break

            next_link = response.get('@odata.nextLink')
            if next_link is not None:
                endpoint = next_link
            else:
                break

            if params is not None:
                if '$top' in params:
                    del params['$top']

                if '$filter' in params:
                    del params['$filter']

            if params == {}:
                params = None

        return phantom.APP_SUCCESS, list_items

    def _get_alert_vendor_info(self, action_result, endpoint):
        """ This function is used to Check for valid alert id
            and then get vendor information

        :param :action_result: object of ActionResult class
               :endpoint: Endpoint to get data of alert
        :return: status success/failure
        """
        ret_val, alert = self._update_request(action_result, endpoint)
        if phantom.is_fail(ret_val):
            message = MS_GRAPHSECURITYAPI_ALERT_FAILED_MSG
            if str(action_result.get_message()) == MS_GRAPHSECURITYAPI_TOKEN_NOT_AVAILABLE_MSG:
                message = action_result.get_message()
            return action_result.set_status(phantom.APP_ERROR, status_message=message), None

        vendor_info = {}
        vendor_info["provider"] = alert['vendorInformation']['provider']
        vendor_info["vendor"] = alert['vendorInformation']['vendor']

        return phantom.APP_SUCCESS, vendor_info

    def _handle_list_alerts(self, param):
        """ This function is used to list all the alerts.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        filter = ''
        and_for_append = ''
        and_flag = False
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        status = param.get(MS_GRAPHSECURITYAPI_STATUS)
        provider = param.get(MS_GRAPHSECURITYAPI_PROVIDER)
        source_address = param.get(MS_GRAPHSECURITYAPI_SOURCE_ADDRESS)

        if status:
            status = self.convert_paramter_to_list(status)
            if len(status) < 1:
                return action_result.set_status(phantom.APP_ERROR, status_message=MS_GRAPHSECURITYAPI_STATUS_FAILED_MSG)
            if len(status) > 1:
                for st in range(len(status) - 1):
                    filter += "status eq '{}'".format(status[st]) + " or "
                filter += "status eq '{}'".format(status[st + 1])
            else:
                filter += "status eq '{}'".format(status[0])
            and_flag = True

        if provider:
            if and_flag:
                and_for_append = " and "
            filter += and_for_append + "vendorInformation/provider eq '{}'".format(provider)
            and_flag = True

        if source_address:
            if and_flag:
                and_for_append = " and "
            filter += and_for_append + "networkConnections/any(s:s/sourceAddress eq '{source_address}')".\
                format(source_address=source_address)

        endpoint = MS_GRAPHSECURITYAPI_BASE_URL + MS_GRAPHSECURITYAPI_ALERTS_ENDPOINT

        ret_val, alerts = self._paginator(action_result, endpoint, query=filter)
        if phantom.is_fail(ret_val):
            message = MS_GRAPHSECURITYAPI_LIST_ALERTS_FAILED_MSG
            if str(action_result.get_message()) == MS_GRAPHSECURITYAPI_TOKEN_NOT_AVAILABLE_MSG:
                message = action_result.get_message()
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        num_alerts = len(alerts)
        message = MS_GRAPHSECURITYAPI_LIST_ALERTS_PASSED_MSG

        if num_alerts < 1:
            message = MS_GRAPHSECURITYAPI_LIST_ALERTS_NO_ALERT_PASSED_MSG

        for alert in alerts:
            action_result.add_data(alert)

        action_result.update_summary({'total_alerts_returned': num_alerts})

        return action_result.set_status(phantom.APP_SUCCESS, status_message=message.format(num_alerts))

    def _handle_update_alert(self, param):
        """ This function is used to update an alert.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param[MS_GRAPHSECURITYAPI_ALERTID]
        status = param[MS_GRAPHSECURITYAPI_STATUS]
        comment = param.get(MS_GRAPHSECURITYAPI_COMMENT)
        feedback = param.get(MS_GRAPHSECURITYAPI_FEEDBACK)

        endpoint = "{}{}/{}".format(MS_GRAPHSECURITYAPI_BASE_URL, MS_GRAPHSECURITYAPI_ALERTS_ENDPOINT, alert_id)
        ret_val, vendor_info = self._get_alert_vendor_info(action_result, endpoint)

        if phantom.is_fail(ret_val):
            return ret_val

        data = dict()
        if comment:
            data["comments"] = [comment]
        if feedback:
            data["feedback"] = feedback
        data["vendorInformation"] = vendor_info
        data["status"] = status
        data = json.dumps(data)

        # Update alert here
        ret_val, alert = self._update_request(action_result, endpoint, data=data, method="patch")
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, status_message=MS_GRAPHSECURITYAPI_UPDATE_ALERT_FAILED_MSG)

        # Get alert after updation
        ret_val, alert = self._update_request(action_result, endpoint)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, status_message=MS_GRAPHSECURITYAPI_AFTER_UPDATE_ALERT_FAILED_MSG)

        action_result.add_data(alert)
        action_result.update_summary({'alert_updated': alert["id"]})

        return action_result.set_status(phantom.APP_SUCCESS, status_message=MS_GRAPHSECURITYAPI_UPDATE_ALERT_PASSED_MSG)

    def _handle_close_alert(self, param):
        """ This function is used to close an alert.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_id = param[MS_GRAPHSECURITYAPI_ALERTID]
        status = param[MS_GRAPHSECURITYAPI_STATUS]
        comment = param.get(MS_GRAPHSECURITYAPI_COMMENT)
        feedback = param.get(MS_GRAPHSECURITYAPI_FEEDBACK)

        endpoint = "{}{}/{}".format(MS_GRAPHSECURITYAPI_BASE_URL, MS_GRAPHSECURITYAPI_ALERTS_ENDPOINT, alert_id)
        ret_val, vendor_info = self._get_alert_vendor_info(action_result, endpoint)
        if phantom.is_fail(ret_val):
            return ret_val

        data = dict()
        data["vendorInformation"] = vendor_info
        data["status"] = status
        data["closedDateTime"] = datetime.utcnow().strftime(MS_GRAPHSECURITYAPI_DT_STR_FORMAT)

        if feedback:
            data["feedback"] = feedback
        if comment:
            data["comments"] = [comment]

        data = json.dumps(data)

        # Close alert here
        ret_val, alert = self._update_request(action_result, endpoint, data=data, method="patch")
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, status_message=MS_GRAPHSECURITYAPI_CLOSE_ALERT_FAILED_MSG)

        # Get alert after updation
        ret_val, alert = self._update_request(action_result, endpoint)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, status_message=MS_GRAPHSECURITYAPI_AFTER_CLOSE_ALERT_FAILED_MSG)

        action_result.add_data(alert)
        action_result.update_summary({'alert_closed': alert["id"]})

        return action_result.set_status(phantom.APP_SUCCESS, status_message=MS_GRAPHSECURITYAPI_CLOSE_ALERT_PASSED_MSG)

    def _save_artifacts(self, results, key):
        """Ingest all the given artifacts accordingly into the new or existing container.

        Parameters:
            :param results: list of artifacts of alerts results
            :param key: name of the container in which data will be ingested
        Returns:
            :return: None
        """
        # Initialize
        start = 0

        # If not results return
        if not results:
            return

        # Divide artifacts list into chunks which length equals to max_artifacts configured in the asset
        artifacts = [results[i:i + self._max_artifacts] for i in range(start, len(results), self._max_artifacts)]

        for artifacts_list in artifacts:
            container_name = "{} {}".format(key, str(datetime.now()))
            ret_val = self._ingest_artifacts(artifacts_list, container_name)
            if phantom.is_fail(ret_val):
                self.debug_print("Failed to save ingested artifacts in the new container")
                return

    def _ingest_artifacts(self, artifacts, key):
        """Ingest artifacts into the Phantom server.

        Parameters:
            :param action_result: object of ActionResult class
            :param artifacts: list of artifacts
            :param key: name of the container in which data will be ingested
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.debug_print(f"Ingesting {len(artifacts)} artifacts for {key} results into the 'new' container")
        ret_val, message, _ = self._save_ingested(artifacts, key)

        if phantom.is_fail(ret_val):
            self.debug_print("Failed to save ingested artifacts, error msg: {}".format(message))
            return ret_val

        return ret_val

    def _save_ingested(self, artifacts, key):
        """Create new container with given key(name) and save the artifacts.

        Parameters:
            :param artifacts: list of artifacts of IoCs or alerts results
            :param key: name of the container in which data will be ingested
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR), message, cid(container_id)
        """
        container = dict()
        container.update({
            "name": key,
            "description": 'alert ingested using MS Graph API',
            "source_data_identifier": key,
            "artifacts": artifacts
        })
        ret_val, message, cid = self.save_container(container)
        self.debug_print("save_container (with artifacts) returns, value: {}, reason: {}, id: {}".format(ret_val, message, cid))
        return ret_val, message, cid

    def _validate_integers(self, action_result, parameter, key, allow_zero=False):
        """
        Validate an integer.

        Parameters:
            :param action_result: object of ActionResult class
            :param parameter: input parameter
            :param key: string value of parameter name
            :param allow_zero: indicator for given parameter that whether zero value is allowed or not
        Returns:
            :return: status phantom.APP_ERROR/phantom.APP_SUCCESS, integer value of the parameter or None in case of failure
        """

        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, MS_GRAPHSECURITYAPI_VALID_INT_MSG.format(param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, MS_GRAPHSECURITYAPI_VALID_INT_MSG.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, MS_GRAPHSECURITYAPI_NON_NEG_INT_MSG.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, MS_GRAPHSECURITYAPI_NON_NEG_NON_ZERO_INT_MSG.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _check_invalid_since_utc_time(self, time):
        """Determine that given time is not before 1970-01-01T00:00:00Z.

        Parameters:
            :param action_result: object of ActionResult class
            :param time: object of time
        Returns:
            :return: status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        # Check that given time must not be before 1970-01-01T00:00:00Z.
        if time < datetime.strptime("1970-01-01T00:00:00Z", MS_GRAPHSECURITYAPI_DT_STR_FORMAT):
            return phantom.APP_ERROR
        return phantom.APP_SUCCESS

    def _check_date_format(self, action_result, date):
        """Validate the value of time parameter given in the action parameters.

        Parameters:
            :param date: value of time(start/end/reference) action parameter
        Returns:
            :return: status(True/False)
        """
        # Initialize time for given value of date
        time = None
        try:
            # Check for the time is in valid format or not
            time = datetime.strptime(date, MS_GRAPHSECURITYAPI_DT_STR_FORMAT)
            # Taking current UTC time as end time
            end_time = datetime.utcnow()
            # Check for given time is not before 1970-01-01T00:00:00Z
            ret_val = self._check_invalid_since_utc_time(action_result, time)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, MS_GRAPHSECURITYAPI_UTC_SINCE_TIME_ERROR)

            # Checking future date
            if time >= end_time:
                msg = MS_GRAPHSECURITYAPI_GREATER_EQUAL_TIME_ERROR.format(MS_GRAPHSECURITYAPI_CONFIG_TIME_POLL_NOW)
                return action_result.set_status(phantom.APP_ERROR, msg)
        except Exception as e:
            message = "Invalid date string received. Error occurred while checking date format. Error: {}".format(str(e))
            return action_result.set_status(phantom.APP_ERROR, message)
        return phantom.APP_SUCCESS

    def _handle_on_poll(self, param):
        """ This function is used to ingest an alerts.

        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        self.save_progress("In action handler for: {}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()
        last_modified_time = {}
        alerts = []
        max_alerts = None
        params = {'$orderby': 'lastModifiedDateTime asc'}

        # Fetch Max artifacts limit for single container
        max_artifacts = config.get("max_artifacts", MS_GRAPHSECURITYAPI_CONFIG_MAX_ARTIFACTS_DEFAULT)
        ret_val, self._max_artifacts = self._validate_integers(
            action_result, max_artifacts, MS_GRAPHSECURITYAPI_CONFIG_MAX_ARTIFACTS)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Fetch start time for the scheduled run and check date format
        # This time will be used whenever we have to consider run as first run
        time = config.get("start_time_for_poll", "1970-01-01T00:00:00Z")
        ret_val = self._check_date_format(action_result, time)
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR)
        last_modified_time.update({'All': time})

        if self.is_poll_now():
            max_alerts = param[phantom.APP_JSON_ARTIFACT_COUNT]
        elif self._state.get('first_run', True):
            self._state['first_run'] = False
            max_alerts = config.get('first_run_max_alerts', 1000)
        elif self._state.get('last_time'):
            last_modified_time = self._state['last_time']

        endpoint = MS_GRAPHSECURITYAPI_BASE_URL + MS_GRAPHSECURITYAPI_ALERTS_ENDPOINT

        # For getting total providers
        params['$top'] = 1
        ret_val, res = self._update_request(action_result, endpoint, params=params)
        if phantom.is_fail(ret_val):
            message = "On-poll action failed"
            if str(action_result.get_message()) == MS_GRAPHSECURITYAPI_TOKEN_NOT_AVAILABLE_MSG:
                message = action_result.get_message()
            return action_result.set_status(phantom.APP_ERROR, status_message=message)

        top_one_alerts = res.get("value")

        # Get total provider and create dictonary
        providers = dict()
        for alert in top_one_alerts:
            providers.update({alert['vendorInformation']['provider']: list()})

        if max_alerts and max_alerts <= MS_GRAPHSECURITYAPI_TOP_PARAM_UPPER_LIMIT:
            params['$top'] = max_alerts
        else:
            params['$top'] = MS_GRAPHSECURITYAPI_TOP_PARAM_UPPER_LIMIT

        for provider in providers.keys():

            params['$filter'] = "vendorInformation/provider eq '{}'".format(provider)

            all_time = last_modified_time.get('All')
            provider_time = last_modified_time.get(provider)
            time = provider_time or all_time
            params['$filter'] += "and lastModifiedDateTime ge {0}".format(time)

            ret_val, alerts = self._paginator(action_result, endpoint, params=params, limit=max_alerts)
            if phantom.is_fail(ret_val):
                message = "On-poll action failed"
                if str(action_result.get_message()) == MS_GRAPHSECURITYAPI_TOKEN_NOT_AVAILABLE_MSG:
                    message = action_result.get_message()
                return action_result.set_status(phantom.APP_ERROR, status_message=message)

            providers[provider].extend(alerts)

        # Ingest the alerts
        for key, vals in providers.items():
            artifacts = []
            try:
                self.debug_print("Try to create artifacts for the alerts")
                # Create artifacts from the alerts
                artifacts = self._create_alert_artifacts(vals)
            except Exception as e:
                self.debug_print("Error occurred while creating artifacts for alerts. Error: {}".format(str(e)))
                # Make alerts as empty list
                vals = list()

            # Save artifacts for alerts
            try:
                self.debug_print("Try to ingest artifacts for the alerts")
                self._save_artifacts(artifacts, key=key)
            except Exception as e:
                self.debug_print("Error occurred while saving artifacts for alerts. Error: {}".format(str(e)))
                vals = list()

            if vals and not self.is_poll_now():
                last_time_dict = self._state.get('last_time')
                if not last_time_dict:
                    self._state.update({'last_time': {key: vals[-1]['lastModifiedDateTime']}})
                else:
                    self._state['last_time'].update({key: vals[-1]['lastModifiedDateTime']})

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        self.debug_print("action_id", self.get_action_identifier())

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_alerts': self._handle_list_alerts,
            'update_alert': self._handle_update_alert,
            'close_alert': self._handle_close_alert,
            'on_poll': self._handle_on_poll
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("Reseting the state file with the default format")
            self._state = {
                "app_version": self.get_app_json().get('app_version')
            }
            return self.set_status(phantom.APP_ERROR, MS_GRAPHSECURITYAPI_STATE_FILE_CORRUPT_ERROR)

        # get the asset config
        config = self.get_config()

        self._tenant = config[MS_GRAPHSECURITYAPI_CONFIG_TENANT_ID]
        self._client_id = config[MS_GRAPHSECURITYAPI_CONFIG_CLIENT_ID]
        self._client_secret = config[MS_GRAPHSECURITYAPI_CONFIG_CLIENT_SECRET]
        self._access_token = self._state.get(MS_GRAPHSECURITYAPI_JSON_TOKEN, {}).get(MS_GRAPHSECURITYAPI_JSON_ACCESS_TOKEN)
        self._refresh_token = self._state.get(MS_GRAPHSECURITYAPI_JSON_TOKEN, {}).get(MS_GRAPHSECURITYAPI_JSON_REFRESH_TOKEN)
        self._max_artifacts = None
        # self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.

        :return: status (success/failure)
        """

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import argparse
    import sys

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            timeout = MS_GRAPHSECURITYAPI_DEFAULT_REQUEST_TIMEOUT
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=False, timeout=timeout)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={}'.format(csrftoken)
            headers['Referer'] = BaseConnector._get_phantom_base_url() + 'login'

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=False, data=data, headers=headers, timeout=timeout)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: {}".format(str(e)))
            sys.exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MicrosoftSecurityAPIConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
