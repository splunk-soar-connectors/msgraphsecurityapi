# File: microsoftgraphsecurityapi_consts.py
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

# General constants
MS_GRAPHSECURITYAPI_LOGIN_BASE_URL = 'https://login.microsoftonline.com'
MS_GRAPHSECURITYAPI_BASE_URL = "https://graph.microsoft.com/v1.0"
MS_GRAPHSECURITYAPI_SERVER_TOKEN_URL = '/{tenant_id}/oauth2/v2.0/token'

# Action endpoints
MS_GRAPHSECURITYAPI_SELF_ENDPOINT = '/me'
MS_GRAPHSECURITYAPI_ALERTS_ENDPOINT = '/security/alerts'

# Config and JSON parameters
MS_GRAPHSECURITYAPI_CONFIG_TENANT_ID = 'tenant_id'
MS_GRAPHSECURITYAPI_CONFIG_CLIENT_ID = 'client_id'
MS_GRAPHSECURITYAPI_CONFIG_CLIENT_SECRET = 'client_secret'  # pragma: allowlist secret
MS_GRAPHSECURITYAPI_JSON_TOKEN = 'token'
MS_GRAPHSECURITYAPI_JSON_ACCESS_TOKEN = 'access_token'
MS_GRAPHSECURITYAPI_JSON_REFRESH_TOKEN = 'refresh_token'
MS_GRAPHSECURITYAPI_REST_REQUEST_SCOPE = 'offline_access group.readwrite.all user.readwrite.all \
    securityevents.readwrite.all securityactions.readwrite.all'
MS_GRAPHSECURITYAPI_STATUS = 'status'
MS_GRAPHSECURITYAPI_PROVIDER = 'provider'
MS_GRAPHSECURITYAPI_SOURCE_ADDRESS = 'source_address'
MS_GRAPHSECURITYAPI_ALERTID = 'alert_id'
MS_GRAPHSECURITYAPI_COMMENT = 'comment'
MS_GRAPHSECURITYAPI_FEEDBACK = 'feedback'
MS_GRAPHSECURITYAPI_FEEDBACK = 'feedback'
MS_GRAPHSECURITYAPI_RESOLVED_STATUS = "resolved"

# URL endpoints
MS_GRAPHSECURITYAPI_ASSET_INFO_URL = '/asset/{asset_id}'
MS_GRAPHSECURITYAPI_SYS_INFO_URL = '/system_info'
MS_GRAPHSECURITYAPI_ADMIN_CONSENT_URL = '/{tenant_id}/adminconsent?client_id={client_id}&redirect_uri={redirect_uri}&state={state}'
MS_GRAPHSECURITYAPI_AUTHORIZE_URL = '/{tenant_id}/oauth2/v2.0/authorize?client_id={client_id}&redirect_uri={redirect_uri}' \
                   '&response_type={response_type}&state={state}&scope={scope}&response_mode={resp_mode}'

# Message constants
MS_GRAPHSECURITYAPI_TOKEN_EXPIRED_MSG = 'Access token has expired'
MS_GRAPHSECURITYAPI_MAKING_CONNECTION_MSG = 'Making Connection...'
MS_GRAPHSECURITYAPI_CODE_RECEIVED_MSG = 'Code Received'
MS_GRAPHSECURITYAPI_OAUTH_URL_MSG = 'Using OAuth URL:'
MS_GRAPHSECURITYAPI_GOT_CURRENT_USER_INFO_MSG = 'Got current user info'
MS_GRAPHSECURITYAPI_ADMIN_CONSENT_FAILED_MSG = 'Admin consent not received'
MS_GRAPHSECURITYAPI_ADMIN_CONSENT_PASSED_MSG = 'Admin consent Received'
MS_GRAPHSECURITYAPI_CURRENT_USER_INFO_MSG = 'Getting info about the current user to verify token'
MS_GRAPHSECURITYAPI_AUTHORIZE_USER_MSG = 'Please authorize user in a separate tab using URL'
MS_GRAPHSECURITYAPI_REST_URL_NOT_AVAILABLE_MSG = 'Rest URL not available. Error: {error}'
MS_GRAPHSECURITYAPI_TEST_CONNECTIVITY_PASSED_MSG = 'Test connectivity passed'
MS_GRAPHSECURITYAPI_TEST_CONNECTIVITY_FAILED_MSG = 'Test connectivity failed'
MS_GRAPHSECURITYAPI_LIST_ALERTS_FAILED_MSG = 'List alerts action failed'
MS_GRAPHSECURITYAPI_UPDATE_ALERT_FAILED_MSG = 'Update alert action failed'
MS_GRAPHSECURITYAPI_AFTER_UPDATE_ALERT_FAILED_MSG = 'Failed to get updated alert'
MS_GRAPHSECURITYAPI_CLOSE_ALERT_FAILED_MSG = 'Close alert action failed'
MS_GRAPHSECURITYAPI_AFTER_CLOSE_ALERT_FAILED_MSG = 'Failed to get closed alert'
MS_GRAPHSECURITYAPI_LIST_ALERTS_PASSED_MSG = 'Successfully retrieved {} alerts'
MS_GRAPHSECURITYAPI_LIST_ALERTS_NO_ALERT_PASSED_MSG = 'Received {} alert. Please verify given parameters'
MS_GRAPHSECURITYAPI_UPDATE_ALERT_PASSED_MSG = 'Successfully updated alert'
MS_GRAPHSECURITYAPI_CLOSE_ALERT_PASSED_MSG = 'Successfully closed alert'
MS_GRAPHSECURITYAPI_ALERT_FAILED_MSG = 'Please enter valid alert id'
MS_GRAPHSECURITYAPI_STATUS_FAILED_MSG = 'Please enter valid status states'
MS_GRAPHSECURITYAPI_TAGS_FAILED_MSG = 'Please enter valid tags'
MS_GRAPHSECURITYAPI_CONFIG_MAX_ARTIFACTS = "'Max allowed artifacts in a single container' asset configuration"
MS_GRAPHSECURITYAPI_CONFIG_MAX_ALERTS = "'Max allowed alerts in a single call' asset configuration"
MS_GRAPHSECURITYAPI_ERROR_CODE_UNAVAILABLE = 'Error code unavailable'
MS_GRAPHSECURITYAPI_ERROR_MSG_UNKNOWN = 'Unknown error occurred. Please check the asset configuration and|or action parameters.'
MS_GRAPHSECURITYAPI_GENERATING_ACCESS_TOKEN_MSG = 'Generating access token'
MS_GRAPHSECURITYAPI_TOKEN_NOT_AVAILABLE_MSG = 'Token not available. Please run test connectivity first.'
MS_GRAPHSECURITYAPI_BASE_URL_NOT_FOUND_MSG = 'Splunk SOAR Base URL not found in System Settings. \
                            Please specify this value in System Settings.'
MS_GRAPHSECURITYAPI_ADMIN_CONSENT_MSG = 'Please hit the mentioned URL in another tab of browser \
     to authorize the user and provide the admin consent: '
MS_GRAPHSECURITYAPI_STATE_FILE_CORRUPT_ERROR = "Error occurred while loading the state file due to its unexpected format.\
     Resetting the state file with the default format. Please try again."
MS_GRAPHSECURITYAPI_INVALID_PERMRISSION_ERR = "Error occurred while saving the newly generated access token \
     (in place of the expired token) in the state file. \
     Please check the owner, owner group, and the permissions of the state file. The Splunk SOAR  \
     user should have the correct access rights and ownership for the corresponding state file \
     (refer to readme file for more information)."
MS_GRAPHSECURITYAPI_ENCRYPTION_ERR = "Error occurred while encrypting the state file"
MS_GRAPHSECURITYAPI_DECRYPTION_ERR = "Error occurred while decrypting the state file"

# Constants relating to 'validate_integers'
MS_GRAPHSECURITYAPI_VALID_INT_MSG = "Please provide a valid integer value in the '{param}' parameter"
MS_GRAPHSECURITYAPI_NON_NEG_NON_ZERO_INT_MSG = "Please provide a valid non-zero positive integer value in '{param}' parameter"
MS_GRAPHSECURITYAPI_NON_NEG_INT_MSG = "Please provide a valid non-negative integer value in the '{param}' parameter"

MS_GRAPHSECURITYAPI_UTC_SINCE_TIME_ERROR = "Please provide time in the span of UTC time since Unix epoch 1970-01-01T00:00:00Z."
MS_GRAPHSECURITYAPI_GREATER_EQUAL_TIME_ERR = 'Invalid {0}, can not be greater than or equal to current UTC time'
MS_GRAPHSECURITYAPI_CONFIG_TIME_POLL_NOW = "'Time range for POLL NOW' or 'Start Time for Schedule/Manual POLL' asset configuration parameter"

# Time constants
MS_GRAPHSECURITYAPI_TC_STATUS_SLEEP = 3
MS_GRAPHSECURITYAPI_CONFIG_MAX_ARTIFACTS_DEFAULT = 500
MS_GRAPHSECURITYAPI_AUTHORIZE_WAIT_TIME = 15
MS_GRAPHSECURITYAPI_DT_STR_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

MS_GRAPHSECURITYAPI_DEFAULT_REQUEST_TIMEOUT = 30  # in seconds
MS_GRAPHSECURITYAPI_TOP_PARAM_UPPER_LIMIT = 1000
