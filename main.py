# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""An App Engine app to generate and update user's google domain passwords.

This app enables users to generate new passwords for their google domain
accounts, which they can then use for their non-saml clients.

"""

import csv
from datetime import datetime
from datetime import timedelta
import json
import logging
import os
import random
import re
import string
import StringIO
import urllib
import uuid
import xml.etree.ElementTree as etree

from apiclient import errors
from apiclient.discovery import build
import httplib2
import jinja2
from models.password_generation import PasswordGeneration
from models.password_keeper import PasswordKeeper
from models.session import Session
from models.setting import Setting
from models.webapp2_secret_key import Webapp2SecretKey
from oauth2client import appengine
from oauth2client import client
from password_crypto_helper import PasswordCryptoHelper
from password_generator_helper import PasswordGeneratorHelper
import webapp2
from webapp2_extras import sessions
from wtforms import Form
from wtforms import TextField
from wtforms import validators
from wtforms.ext.appengine.ndb import model_form
from xsrf_helper import XsrfHelper

from google.appengine.api import datastore_errors
from google.appengine.api import mail
from google.appengine.api import memcache
from google.appengine.ext import ndb
from google.appengine.api import users


_LOG = logging.getLogger('google_password_generator.main')

JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(__file__),
                     'templates')),
    extensions=['jinja2.ext.autoescape'])

ADMIN_PAGE_BASE_URL = '/admin'

VISUALLY_AMBIGUOUS_CHAR_SET = 'Il|1O0'

DATABASE_EXCEPTION_LOG_MESSAGE = 'Encountered database exception: %s'

DEFAULT_EMAIL_BODY_FOR_IOS_PROFILE_DOWNLOAD_NOTIFICATION = (
    'Your requested password has been generated for you using Password'
    ' Generator. Use the link below to configure other iOS devices'
    ' using the password generated. NOTE: This link below will expire'
    ' in 15 minutes.')

DEFAULT_EMAIL_SUBJECT_FOR_IOS_PROFILE_DOWNLOAD_NOTIFICATION = (
    'Password Generator iOS Notification')

DOMAIN_USER_INFO_NAMESPACE = 'pwg_domain_user_info_namespace'

DOWNLOAD_REPORT_BASE_URL = '/download_report'

DOWNLOAD_IOS_PROFILE_BASE_URL = '/download_ios_profile'

GROUP_MEMBERSHIP_INFO_NAMESPACE = 'pwg_group_membership_info_namespace'

HTML5_SAFE_DATE_FORMATTING = '%Y-%m-%d'

IS_MEMCACHE_SET_LOG_MESSAGE = 'Is memcache set for %s: %s'

# This will create a window where decommissioned admin or authorized group users
# can still have access to the app.
MEMCACHE_EXPIRATION_TIME_IN_SECONDS = 3600

NO_ACCESS_TO_DOWNLOAD_IOS_PROFILE_ERROR_MESSAGE = (
    'You do not have access to download iOS profile.  Either the download '
    'feature is not enabled, you are not using an iOS device, or you are not '
    'using the Safari browser on iOS.')

NO_ACCESS_TO_DOWNLOAD_IOS_PROFILE_LOG_MESSAGE = (
    'No access to download iOS profile for %s.  Either the download feature is '
    'not enabled, this is not an iOS device, or this is not safari browser.')

PASSWORD_CANNOT_BE_SAVED_ERROR_MESSAGE = (
    'Your password can not be saved due to database error.  Please try to '
    'generate a new password again in a few moments.')

PASSWORD_HAS_EXPIRED_ERROR_MESSAGE = ('Your iOS profile can not be downloaded '
                                      'because your password has expired.')

PASSWORD_HAS_EXPIRED_LOG_MESSAGE = 'Password has expired for %s.'

USER_IS_APPENGINE_ADMIN_LOG_MESSAGE = '%s is appengine admin.'

USER_IS_DOMAIN_ADMIN_LOG_MESSAGE = '%s is domain admin.'

USER_IS_NOT_ADMIN_LOG_MESSAGE = ('%s (user_id: %s) is not admin and attempting '
                                 'to access the page.')

NO_ACCESS_TO_REQUESTED_PAGE_ERROR_MESSAGE = ('You do not have access to the '
                                             'requested page.')

XSRF_TOKEN_IS_INVALID_ERROR_MESSAGE = (
    'The security protection token provided in your request is invalid. Please '
    'reload the website and try your request again.')

XSRF_TOKEN_IS_INVALID_LOG_MESSAGE = (
    'Rendering error page for %s (user_id: %s) due to invalid xsrf token.')


def Handle401(request, response, exception):  # pylint: disable=unused-argument
  """Returns a webapp2 response, with a 401 unauthorized http status.

  We are not logging the exception here because the actual http code might be
  404 or 400, and is logged elsewhere.  This is almost a stub method so that we
  can use the abort() to stop code execution.

  Args:
    request: webapp2 request object
    response: webapp2 response object
    exception: exception object
  """
  response.write('You have not been granted access to this service.  '
                 'Please contact your Admin for access.')
  response.set_status(401)


class ApiHelper(object):
  """Helper class for Google Apps APIs used by various handlers.

  Data structure of the domain user info is here.
  https://developers.google.com/admin-sdk/directory/v1/reference/users
  """
  API_SCOPE = (
      'https://www.googleapis.com/auth/admin.directory.user '
      'https://www.googleapis.com/auth/admin.directory.group.member.readonly')
  API_SERVICE_NAME = 'admin'
  DIRECTORY_API_VERSION = 'directory_v1'

  def _GetPrivateKey(self, private_key_filename):
    """Get the PEM certificate.

    Args:
      private_key_filename: string of the private key filename

    Returns:
      string content of the private key (i.e. PEM certificate)
    """
    with open(private_key_filename, 'rb') as f:
      return f.read()

  def _GetAuthorizedHttp(self, current_settings):
    """Get the authorized http from the signed jwt assertion credentials.

    The credentials will be stored in datastore.  The client library will find
    it, validate it, and refresh it.

    Args:
      current_settings: An appengine datastore entity for the current_settings.

    Returns:
      authorized http
    """
    _LOG.info('Creating credentials storage in datastore.')
    credentials_in_storage = appengine.StorageByKeyName(
        appengine.CredentialsModel, 'password_generator', 'credentials')

    _LOG.debug('Getting credentials from storage.')
    credentials = credentials_in_storage.get()
    if credentials:
      _LOG.debug('Successfully got credentials from storage.')
    else:
      _LOG.debug('Credentials not in storage. Creating new credentials.')
      credentials = client.SignedJwtAssertionCredentials(
          current_settings.service_account,
          self._GetPrivateKey(current_settings.private_key_filename),
          self.API_SCOPE,
          sub=current_settings.domain_admin_account)
      credentials_in_storage.put(credentials)
      _LOG.debug('Successfully put credentials in storage.')

    return credentials.authorize(httplib2.Http())

  def _BuildDirectoryApiService(self, current_settings):
    """Build the directory api service.

    Args:
      current_settings: An appengine datastore entity for the current_settings.

    Returns:
      service object for interacting with the directory api

    Raises:
      InvalidPemException: An exception that that the PEM file content is not
          valid.
    """
    try:
      return build(
          serviceName=self.API_SERVICE_NAME,
          version=self.DIRECTORY_API_VERSION,
          http=self._GetAuthorizedHttp(current_settings))
    except NotImplementedError:
      ndb.Key('CredentialsModel', 'password_generator').delete()
      if memcache.flush_all():
        _LOG.debug('Memcache flushed successfully due to invalid service '
                   'account credentials.')
      else:
        _LOG.debug('Memcache not flushed successfully due to invalid service '
                   'account credentials.')
      raise Exception('The service account credentials are invalid.  '
                      'Check to make the you have a valid PEM file and you '
                      'have removed any extra data attributes that may have '
                      'been written to the PEM file when converted from '
                      'PKCS12.  The existing PEM key has been revoked and '
                      'needs to be updated with a new valid key.')

  def GetGroupMembershipInfo(self, current_user, current_settings):
    """Get the Google Group membership info of a user.

    The memcache will be checked first.  If not in memcache, we will then
    make the api call, and then save into memcache for future use.

    Args:
      current_user: appengine user object
      current_settings: An appengine datastore entity for the current_settings.

    Returns:
      group_membership_info: A dictionary of the group membership info.
        https://developers.google.com/admin-sdk/directory/v1/reference/members

    Raises:
      HttpError: An error occurred when looking up group membership info by the
        apiclient library.
    """
    _LOG.info('Retrieving group membership for %s.', current_user.nickname())
    group_membership_info = memcache.get(
        current_user.email(),
        namespace=GROUP_MEMBERSHIP_INFO_NAMESPACE)

    if not group_membership_info:
      try:
        group_membership_info = self._BuildDirectoryApiService(
            current_settings).members().get(
                groupKey=current_settings.group_with_access_permission,
                memberKey=current_user.email()).execute()
        is_memcache_set = memcache.set(
            current_user.email(), group_membership_info,
            namespace=GROUP_MEMBERSHIP_INFO_NAMESPACE,
            time=MEMCACHE_EXPIRATION_TIME_IN_SECONDS)
        _LOG.debug(IS_MEMCACHE_SET_LOG_MESSAGE, 'group_membership_info',
                   is_memcache_set)
      except errors.HttpError:
        raise

    _LOG.debug('Successfully retrieved group membership info for %s.',
               current_user.nickname())
    return group_membership_info

  def GetDomainUserInfo(self, current_user, current_settings):
    """Get the domain user info.

    The memcache will be checked first.  If not in memcache, we will then
    make the api call, and then save into memcache for future use.

    Args:
      current_user: appengine user object
      current_settings: An appengine datastore entity for the current_settings.

    Returns:
      domain_user_info: A dictionary of the domain user info.
    """
    _LOG.info('Getting domain info for %s.', current_user.nickname())
    domain_user_info = memcache.get(current_user.email(),
                                    namespace=DOMAIN_USER_INFO_NAMESPACE)

    if not domain_user_info:
      domain_user_info = self._BuildDirectoryApiService(
          current_settings).users().get(userKey=current_user.email()).execute()
      is_memcache_set = memcache.set(
          current_user.email(), domain_user_info,
          namespace=DOMAIN_USER_INFO_NAMESPACE,
          time=MEMCACHE_EXPIRATION_TIME_IN_SECONDS)
      _LOG.debug(IS_MEMCACHE_SET_LOG_MESSAGE, 'domain_user_info',
                 is_memcache_set)

    _LOG.debug('Domain user info: %s', domain_user_info)
    return domain_user_info

  def UpdateDomainUserInfo(self, current_user, current_settings,
                           new_domain_user_info):
    """Updates the domain user info.

    Args:
      current_user: appengine user object
      current_settings: An appengine datastore entity for the current_settings.
      new_domain_user_info: A dictionary of the domain user with the new info
          to be updated.
    """
    _LOG.info('Updating domain info for %s.', current_user.nickname())
    updated_domain_user_info = self._BuildDirectoryApiService(
        current_settings).users().update(
            userKey=current_user.email(), body=new_domain_user_info).execute()
    _LOG.debug('Updated domain user info: %s', updated_domain_user_info)


class PWGBaseHandler(webapp2.RequestHandler, XsrfHelper,
                     PasswordGeneratorHelper):
  """Base handler that all the other handlers will subclass.

  Define the default template rendering.

  Define the default handling of exceptions by directing users to error page,
  show them the specific error, and log the stack trace for troubleshooting.

  The dispatch() and session() are adopted from webapp2 example.
  http://webapp-improved.appspot.com/guide/extras.html
  """

  def dispatch(self):  # pylint: disable=g-bad-name
    self.session_store = sessions.get_store(request=self.request)

    try:
      webapp2.RequestHandler.dispatch(self)
    finally:
      self.session_store.save_sessions(self.response)

  @webapp2.cached_property
  def session(self):  # pylint: disable=g-bad-name
    return self.session_store.get_session(backend='datastore')

  def _SanitizeFormAndFields(self, form):
    """Get a sanitized form and a dictionary of sanitized form fields.

    Args:
      form: a wtforms form object

    Returns:
      form: a sanitized wtforms form object
      sanitized_fields: a dictionary of sanitized form fields, where k,v is
        field.name,field.data
    """
    sanitized_fields = {}
    for field in form:
      if isinstance(field.data, basestring):
        field.data = self.SanitizeText(field.data)
      sanitized_fields.update({field.name: field.data})

    return form, sanitized_fields

  def _PreventUnauthorizedUserAccess(self):
    """Prevent unauthorized users from accessing this service.

    If user is a member of a group, then he has access to this service.  The way
    that the directory members api works is that it will return a members object
    if the user is in the group.  Otherwise, it will just throw HttpError if
    the user is not in the group.  Will use a 401 code as a catch-all 4XX code
    for aborting further code execution.

    Raises:
      HttpError: An error occurred when looking up group membership info by the
        apiclient library.
    """
    _LOG.info('Checking if %s can access this service.',
              self.current_user.nickname())
    try:
      group_membership_info = ApiHelper().GetGroupMembershipInfo(
          self.current_user, self.current_settings)
      _LOG.info('%s is a %s of the group that can access this service.',
                self.current_user.nickname(), group_membership_info['role'])
    except errors.HttpError as e:
      error = json.loads(e.content).get('error')
      if error.get('code') == 404:
        _LOG.warning('%s does not have access to this service.  The apiclient '
                     'is returning: %s, %s', self.current_user.nickname(),
                     error.get('code'), error.get('message'))
        _LOG.exception(e)
        self.abort(401)
      else:
        raise

  def _AbortIfSettingDatastoreDoesNotExist(self, current_setting):
    """Abort request execution if setting datastore does not exist.

    The current_setting datastore entity will be checked.  If it's null, then it
    means the setting datastore does not exist.

    Args:
      current_setting: A setting datastore entity representing current settings.

    Raises:
      Exception: A generic exception with message that datastore does not exist.
    """
    if not self.current_settings:
      is_appengine_admin = users.is_current_user_admin()
      if is_appengine_admin:
        exception_message = ('The setting database does not exist and needs to '
                             'be configured at the admin page: %s%s' %
                             (self.request.host_url, ADMIN_PAGE_BASE_URL))
      else:
        exception_message = ('Please let your appengine admin know that the '
                             'setting database does not exist and needs to '
                             'be configured.')
      _LOG.warning(exception_message)
      raise Exception(exception_message)

  def _InitiatePWG(self):
    """Get and set the initial settings and values of the application state.

    We cannot retrieve these info in __init__() because any exception from these
    methods within __init__() will not be dispatched to handle_exception(),
    and will cause raw stack trace to be displayed to the user.  So for a better
    user experience, we will opt to retrieve these info in the handlers
    instead of __init__().

    NB: This method always needs to be the first to be called in any handlers.
    """
    self.current_user = users.get_current_user()

    self.current_settings = Setting.GetCurrentSettings()
    self._AbortIfSettingDatastoreDoesNotExist(self.current_settings)

    self.domain_user_info = ApiHelper().GetDomainUserInfo(
        self.current_user, self.current_settings)
    self._PreventUnauthorizedUserAccess()

  def _RenderTemplate(self, html_filename, **kwargs):
    """Renders the template for the request page.

    We are not returning a response because overriding the dispatch() seems to
    have broken the response from being returned properly.

    Args:
      html_filename: the name of the html file to render
      **kwargs: dict of the items to render for the template, where the key is
          template field name, and the value is the template field value

          {user=self.current_user,
           all_settings=Setting.GetAllValues(),
           password_generations=password_generations,
           is_admin=is_admin}

    Returns:
      A response containing the rendered template.
    """
    _LOG.debug('Template values are: {0}'.format(kwargs))
    _LOG.info('Rendering {0} .'.format(html_filename))
    self.response.headers['X-Frame-Options'] = 'DENY'
    self.response.write(JINJA_ENVIRONMENT.get_template(
        html_filename).render(kwargs))

  def _RenderNoAccessIsAllowedErrorPage(self):
    _LOG.warning(USER_IS_NOT_ADMIN_LOG_MESSAGE, self.current_user.nickname(),
                 self.current_user.user_id())
    self._RenderTemplate(
        'error.html',
        error_message=NO_ACCESS_TO_REQUESTED_PAGE_ERROR_MESSAGE,
        is_admin=self.domain_user_info.get('isAdmin'))

  def _RenderErrorPage(self, log_message, error_message, is_admin):
    _LOG.warning('%s, %s', log_message, self.current_user.nickname())
    self._RenderTemplate(
        'error.html',
        error_message=error_message,
        is_admin=is_admin)

  def handle_exception(self, exception, debug):  # pylint: disable=g-bad-name
    _LOG.exception(exception)
    _LOG.debug('Is the web application in debug mode: {0}'.format(debug))

    # A best effort to get some settings so that we can display a more
    # user-friendly error page.  Otherwise, display as clean a page as we can.
    try:
      self._RenderTemplate(
          'error.html',
          error_message=self.current_settings.error_message,
          exception_message=exception,
          is_admin=self.domain_user_info.get('isAdmin'))
    except:  # pylint: disable=bare-except
      self._RenderTemplate(
          'error.html',
          exception_message=exception)


class RequestPageHandler(PWGBaseHandler):
  """Handler for the initial/request page.

  This is responsible for generating the initial landing page for the user, who
  would request a new password to be generated, and then posted to the
  result page.  The entry point is "/".
  """

  def get(self):  # pylint: disable=g-bad-name
    """Get method for ResultPageHandler."""
    self._InitiatePWG()
    self.session['xsrf_token'] = self.GenerateXsrfToken(self.current_user)
    self._RenderTemplate(
        'request.html',
        xsrf_token=self.session['xsrf_token'],
        user_fullname=self.domain_user_info['name']['fullName'],
        is_admin=self.domain_user_info.get('isAdmin'),
        create_new_password_message=
        self.current_settings.create_new_password_message)


class ResultPageHandler(PWGBaseHandler):
  """Handler for the result page.

  This receives the post request from the request page for a new password.  It
  will generate a random password, update it via the directory api, and then
  show the new password to the user.  The entry point is "/result".
  """

  def __init__(self, request, response):
    super(ResultPageHandler, self).__init__(request, response)
    self.unsafe_characters_for_jinja = re.compile(r'(\'|"|\\|/|\.|<|>|`)')
    # hackery to make the pipe character replaceable without using raw prefix
    # pylint: disable=anomalous-backslash-in-string
    self.visually_ambiguous_char_set = re.compile(
        '|'.join(VISUALLY_AMBIGUOUS_CHAR_SET).replace('||', '|\|'))
    # pylint: enable=anomalous-backslash-in-string

  class PasswordGenerationForm(Form):
    reason = TextField('Reason', [validators.Required()])

  def _GenerateDownloadUrlForIOSProfile(self, xsrf_token, password_key):
    """Helper to cleanly build a URL.

    Args:
      xsrf_token: A string of the xsrf token.
      password_key: A string of the password key.

    Returns:
      A string for the URL base and parameters e.g.
        https://foobar.appspot.com/url_base?parameter1=abc&parameter2=xyz
    """
    return ''.join([self.request.host_url, DOWNLOAD_IOS_PROFILE_BASE_URL, '?',
                    urllib.urlencode({'xsrf_token': xsrf_token,
                                      'password_key': password_key})])

  def _EmailDownloadUrlForIOSProfile(self, download_url):
    """Email a link to download the iOS profile for user.

    Args:
      download_url: a string for the URL base and parameters e.g.
        https://foobar.appspot.com/url_base?parameter1=abc&parameter2=xyz
    """
    email_sender = self.current_settings.domain_admin_account
    email_recipient = self.current_user.email()
    email_subject = (self.current_settings
                     .email_subject_for_ios_profile_download_notification)
    email_body = ''.join([self.current_settings
                          .email_body_for_ios_profile_download_notification,
                          '\n\n', download_url])
    mail.send_mail(email_sender, email_recipient, email_subject, email_body)
    _LOG.debug('Finished sending email to %s', email_recipient)

  def _BuildIOSProfile(self, decrypted_password):
    """Build a new iOS profile with new settings.

    The password has to be in cleartext in the iOS profile xml.

    The iOS profile template is xml, but it's rather unstructured.
    The data structure corresponds to the sample profile at:
    https://developer.apple.com/library/ios/featuredarticles
    /iPhoneConfigurationProfileRef/iPhoneConfigurationProfileRef.pdf

    For example:
      <xml header>
      <doctype>
      <plist>
        <dict>
          <array>
            <dict>
              <key>Host</key>
              <string>m.google.com</string>
              <key>MailNumberOfPastDaysToSync</key>
              <integer>0</integer>
              <key>Password</key>
              <string>password</string>
            </dict>
          </array>
        </dict>
      </plist>

    An example of UUID that we will generate can be found here:
    http://en.wikipedia.org/wiki/Universally_unique_identifier#Definition

    Args:
      decrypted_password: string of the decrypted password

    Returns:
      A string of an iOS profile xml file with the new configurations.
        Data structure as above.
    """
    _LOG.info('Building iOS profile for %s.',
              self.current_user.nickname())
    ios_profile = etree.parse(
        self.current_settings.ios_profile_template_filename)
    ios_profile_strings = ios_profile.findall('.//string')

    # Note: If the xml schema changes, the elements might not be in the same
    # position.
    password = ios_profile_strings[1]
    password.text = decrypted_password

    payload_identifiers = [ios_profile_strings[4], ios_profile_strings[12]]
    for payload_identifier in payload_identifiers:
      payload_identifier.text = self.request.headers.get('User-Agent')

    new_uuid = str(uuid.uuid1())
    payload_uuids = [ios_profile_strings[7], ios_profile_strings[15]]
    for payload_uuid in payload_uuids:
      payload_uuid.text = new_uuid

    user_name_string = ios_profile_strings[8]
    user_name_string.text = self.current_user.email()

    email_address_string = ios_profile_strings[9]
    email_address_string.text = self.current_user.email()

    xml_header = '<?xml version="1.0" encoding="UTF-8" ?>'
    xml_doctype = ('<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                   '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">')
    ios_profile_instance = '\n'.join([xml_header, xml_doctype,
                                      etree.tostring(ios_profile.getroot())])
    return ios_profile_instance

  def DownloadIOSProfile(self):
    """Download a new instance of the iOS profile from template.

    The data structure corresponds to the sample profile at:
    https://developer.apple.com/library/ios/featuredarticles
    /iPhoneConfigurationProfileRef/iPhoneConfigurationProfileRef.pdf

    Returns:
        A response containing the rendered template.
    """
    self._InitiatePWG()

    if not (self.current_settings.enable_ios_profile_download == 'on' and
            self.IsIOSDevice(self.request.headers.get('User-Agent')) and
            self.IsSafariBrowser(self.request.headers.get('User-Agent'))):
      self._RenderErrorPage((NO_ACCESS_TO_DOWNLOAD_IOS_PROFILE_LOG_MESSAGE
                             % self.current_user.nickname()),
                            NO_ACCESS_TO_DOWNLOAD_IOS_PROFILE_ERROR_MESSAGE,
                            self.domain_user_info.get('isAdmin'))
    elif not self.IsXsrfTokenValid(self.current_user,
                                   self.request.get('xsrf_token'),
                                   self.session.get('xsrf_token')):
      self._RenderErrorPage(XSRF_TOKEN_IS_INVALID_LOG_MESSAGE,
                            XSRF_TOKEN_IS_INVALID_ERROR_MESSAGE,
                            self.domain_user_info.get('isAdmin'))

    else:
      try:
        _LOG.info('iOS profile download requested by: %s',
                  self.current_user.nickname())
        decrypted_password = PasswordCryptoHelper.DecryptPassword(
            PasswordKeeper.GetPassword(self.current_user.email()),
            self.request.get('password_key'))
        downloadable_ios_profile = self._BuildIOSProfile(decrypted_password)

        self.response.headers['X-Frame-Options'] = 'DENY'
        self.response.headers['Content-Type'] = (
            'application/x-apple-aspen-config')
        self.response.headers['Content-Disposition'] = (
            'attachment; filename=ios_profile.xml')
        self.response.headers['Content-Length'] = len(downloadable_ios_profile)
        self.response.write(downloadable_ios_profile)
        PasswordGeneration.StoreIOSProfileDownloadEvent(
            self.current_user,
            self.SanitizeText(self.request.headers.get('User-Agent')),
            self.SanitizeText(self.request.remote_addr))
      except AttributeError:
        self._RenderErrorPage(
            (PASSWORD_HAS_EXPIRED_LOG_MESSAGE % self.current_user.email()),
            PASSWORD_HAS_EXPIRED_ERROR_MESSAGE,
            self.domain_user_info.get('isAdmin'))

  def _GenerateRandomPassword(self, current_settings):
    """Generates a random password.

    Args:
      current_settings: An appengine datastore entity for the current_settings.

    Returns:
      string of a new random password
    """
    password_char_set = string.ascii_lowercase
    if current_settings.use_uppercase_in_password == 'on':
      password_char_set += string.ascii_uppercase
    if current_settings.use_digits_in_password == 'on':
      password_char_set += string.digits
    if current_settings.use_punctuation_in_password == 'on':
      password_char_set += string.punctuation
      # Remove some punctuation characters so that password can be passed safely
      # in jinja template.
      password_char_set = self.unsafe_characters_for_jinja.sub(
          '', password_char_set)

    if current_settings.remove_ambiguous_characters_in_password == 'on':
      password_char_set = self.visually_ambiguous_char_set.sub(
          '', password_char_set)

    chars_for_new_password = []
    # pylint: disable=unused-variable
    for i in range(current_settings.default_password_length):
      chars_for_new_password.append(random.SystemRandom().choice(
          password_char_set))
    # pylint: enable=unused-variable

    return ''.join(chars_for_new_password)

  def _UpdateUserPassword(self, current_user, current_settings):
    """Updates the google apps password for the user.

    Using plaintext password, but is sent securely over encrypted SSL session
    to Google. Google will salt and hash and store the password.  Using plain
    text with the API also allows  Google Apps admins to see the password
    strength indicator of the password on a user account.

    Args:
      current_user: appengine user object
      current_settings: An appengine datastore entity for the current_settings.

    Returns:
      new_password: string of the new password that's been updated for user
    """
    new_password = self._GenerateRandomPassword(current_settings)
    self.domain_user_info['password'] = new_password
    ApiHelper().UpdateDomainUserInfo(current_user, current_settings,
                                     self.domain_user_info)
    PasswordGeneration.StorePasswordGeneration(
        current_user,
        self.SanitizeText(self.request.get('reason')),
        self.SanitizeText(self.request.headers.get('User-Agent')),
        self.SanitizeText(self.request.remote_addr),
        self.current_settings.default_password_length,
        self.SanitizeText(self.current_settings.use_digits_in_password),
        self.SanitizeText(self.current_settings.use_punctuation_in_password),
        self.SanitizeText(self.current_settings.use_uppercase_in_password))
    return new_password

  def post(self):  # pylint: disable=g-bad-name
    """Post method for ResultPageHandler."""
    self._InitiatePWG()
    password_generation_form = self.PasswordGenerationForm(self.request.POST)

    if not self.IsXsrfTokenValid(self.current_user,
                                 self.request.get('xsrf_token'),
                                 self.session.get('xsrf_token')):
      self._RenderErrorPage(XSRF_TOKEN_IS_INVALID_LOG_MESSAGE,
                            XSRF_TOKEN_IS_INVALID_ERROR_MESSAGE,
                            self.domain_user_info.get('isAdmin'))

    elif not password_generation_form.validate():
      _LOG.warning('Password generation form has failed validation.')
      self._RenderTemplate(
          'request.html',
          xsrf_token=self.session.get('xsrf_token'),
          user_fullname=self.domain_user_info['name']['fullName'],
          password_generation_form=password_generation_form,
          is_admin=self.domain_user_info.get('isAdmin'))

    else:
      try:
        new_password = self._UpdateUserPassword(
            self.current_user, self.current_settings)

        if self.current_settings.enable_ios_profile_download == 'on':
          encrypted_password, password_key, crypto_initialization_vector = (
              PasswordCryptoHelper.EncryptPassword(new_password))
          PasswordKeeper.StorePassword(self.current_user.email(),
                                       encrypted_password,
                                       crypto_initialization_vector)
          download_url = self._GenerateDownloadUrlForIOSProfile(
              self.session['xsrf_token'], password_key)
          self._EmailDownloadUrlForIOSProfile(download_url)
        else:
          download_url = None

        self._RenderTemplate(
            'result.html',
            user_fullname=self.domain_user_info['name']['fullName'],
            password=new_password,
            is_admin=self.domain_user_info.get('isAdmin'),
            password_created_message=
            self.current_settings.password_created_message,
            is_safari_browser=self.IsSafariBrowser(
                self.request.headers.get('User-Agent')),
            is_ios_device=self.IsIOSDevice(
                self.request.headers.get('User-Agent')),
            enable_ios_profile_download=
            self.current_settings.enable_ios_profile_download,
            download_url_for_ios_profile=download_url)
      except (datastore_errors.Timeout, datastore_errors.TransactionFailedError,
              datastore_errors.InternalError) as e:
        self._RenderErrorPage((DATABASE_EXCEPTION_LOG_MESSAGE % e),
                              PASSWORD_CANNOT_BE_SAVED_ERROR_MESSAGE,
                              self.domain_user_info.get('isAdmin'))


class ReportPageHandler(PWGBaseHandler):
  """Handler for the report page.

  This is the page where the admin can run reports to see who has used this
  service.  This handler will post to itself to do the actual querying and
  then show the result.  The entry point is "/reporting".
  """

  class ReportingForm(Form):
    """WTForms form object for the reporting page search form."""
    start_date = TextField('Start Date', [validators.Optional()])
    end_date = TextField('End Date', [validators.Optional()])
    user_email = TextField('User Email',
                           [validators.Optional(), validators.Email()])

    # WTForms implicitly calls validate_<field_name> to validate.
    def validate_start_date(self, start_date):
      """Validate that start date has end date for a proper search range."""
      if start_date.data and not self.end_date.data:
        raise validators.ValidationError('Please select an end date along '
                                         'with the start date.')

    def validate_end_date(self, end_date):
      """Validate the end date against multiple criterias."""
      # Validate that end date has start date for a proper search range.
      if end_date.data and not self.start_date.data:
        raise validators.ValidationError('Please select a start date along '
                                         'with the end date.')

      # Validate that end date is after start date.
      start_datetime = datetime.strptime(
          PasswordGeneratorHelper.SanitizeText(self.start_date.data),
          HTML5_SAFE_DATE_FORMATTING)
      end_datetime = datetime.strptime(
          PasswordGeneratorHelper.SanitizeText(end_date.data),
          HTML5_SAFE_DATE_FORMATTING)
      if end_datetime - start_datetime < timedelta(days=0):
        raise validators.ValidationError('Please select an end date after '
                                         'the start date.')

  def _ConvertSearchInputsToValidQueryParameters(self):
    """Convert search inputs to valid search parameters.

    Returns:
      start_datetime: datetime object of the starting date to query
      end_datetime: datetime object of the ending date to query
      user: appengine user object
    """
    start_datetime = None
    end_datetime = None
    user = None

    start_date = self.SanitizeText(self.request.get('start_date'))
    end_date = self.SanitizeText(self.request.get('end_date'))
    user_email = self.SanitizeText(self.request.get('user_email'))

    if start_date:
      start_datetime = datetime.strptime(start_date, HTML5_SAFE_DATE_FORMATTING)
      end_datetime = (datetime.strptime(end_date, HTML5_SAFE_DATE_FORMATTING) +
                      timedelta(hours=23, minutes=59, seconds=59))
    if user_email:
      user = users.User(email=user_email)

    return start_datetime, end_datetime, user

  def _GetPasswordGenerationsBasedOnSearchInputs(self):
    """Get the password generations based on the given search inputs.

    Returns:
      query result as an iterable containing password generation objects
    """
    start_datetime, end_datetime, user_email = (
        self._ConvertSearchInputsToValidQueryParameters())

    if start_datetime and user_email:
      _LOG.info('Search parameters start_date:%s end_date:%s user_email:%s',
                start_datetime, end_datetime, user_email)
      return PasswordGeneration.GetPasswordGenerationsByDateAndUser(
          start_datetime, end_datetime, user_email)
    elif start_datetime and not user_email:
      _LOG.info('Search parameters start_date:%s end_date:%s user_email:%s',
                start_datetime, end_datetime, '')
      return PasswordGeneration.GetPasswordGenerationsByDate(
          start_datetime, end_datetime)
    elif not start_datetime and user_email:
      _LOG.info('Search parameters start_date:%s end_date:%s user_email:%s',
                '', '', user_email)
      return PasswordGeneration.GetPasswordGenerationsByUser(user_email)

  def _GenerateDownloadURLForReport(self, reporting_form):
    """Helper to cleanly build a URL.

    Between the HTTP post and the Report Generation the date values are switched
    from strings to datetime objects to strings again. We need to change them
    back to the expected values to re-query the data.

    Args:
      reporting_form: The WTForm from generating a report.

    Returns:
      A string for the URL base and parameters e.g.
        /url_base?parameter1=abc&parameter2=xyz
    """
    url = {'xsrf_token': self.session.get('xsrf_token')}
    if reporting_form.start_date.data:
      url['start_date'] = reporting_form.start_date.data

    if reporting_form.end_date.data:
      url['end_date'] = reporting_form.end_date.data

    if reporting_form.user_email.data:
      url['user_email'] = reporting_form.user_email.data

    _LOG.debug('Detailed report URL: %s', urllib.urlencode(url))

    return ''.join([DOWNLOAD_REPORT_BASE_URL, '?', urllib.urlencode(url)])

  def _GenerateReportForDownload(self, password_generations):
    """Build a CSV report for download.

    Args:
      password_generations: A list containing password generation objects.

    Returns:
      report_handler: A file handler with csv data.
    """
    report_handler = StringIO.StringIO()
    report_keys = ['User Email', 'Date', 'Reason', 'User-Agent', 'IP Address',
                   'Password Length', 'Digits In Password',
                   'Punctuation In Password', 'Uppercase In Password']
    # If we write a row with a key not present in report_keys we ignore it with
    # extrasaction='ignore' being specified.
    report = csv.DictWriter(report_handler, report_keys,
                            delimiter=',', quotechar='"',
                            quoting=csv.QUOTE_ALL, restval='Unrecorded',
                            extrasaction='ignore',)
    report.writeheader()
    for row in password_generations:
      row_values = [row.user.email(),
                    row.date.strftime('%m/%d/%Y %H:%M'),
                    row.reason,
                    row.user_agent,
                    row.user_ip_address,
                    row.password_length,
                    row.are_digits_used_for_password,
                    row.is_punctuation_used_for_password,
                    row.is_uppercase_used_for_password]
      report.writerow(dict(zip(report_keys, row_values)))

    return report_handler

  def get(self):  # pylint: disable=g-bad-name
    """Get method for ReportPageHandler."""
    self._InitiatePWG()
    if self.domain_user_info['isAdmin']:
      _LOG.info(USER_IS_DOMAIN_ADMIN_LOG_MESSAGE, self.current_user.nickname())
      self.session['xsrf_token'] = self.GenerateXsrfToken(self.current_user)
      self._RenderTemplate(
          'report.html',
          xsrf_token=self.session['xsrf_token'],
          user=self.current_user,
          reporting_form=self.ReportingForm(),
          is_admin=self.domain_user_info.get('isAdmin'))
    else:
      self._RenderNoAccessIsAllowedErrorPage()

  def post(self):  # pylint: disable=g-bad-name
    """Post method for ReportPageHandler."""
    self._InitiatePWG()
    reporting_form = self.ReportingForm(self.request.POST)

    if not self.domain_user_info['isAdmin']:
      self._RenderNoAccessIsAllowedErrorPage()

    elif not self.IsXsrfTokenValid(self.current_user,
                                   self.request.get('xsrf_token'),
                                   self.session.get('xsrf_token')):
      self._RenderErrorPage(XSRF_TOKEN_IS_INVALID_LOG_MESSAGE,
                            XSRF_TOKEN_IS_INVALID_ERROR_MESSAGE,
                            self.domain_user_info.get('isAdmin'))

    elif reporting_form.validate():
      password_generations = self._GetPasswordGenerationsBasedOnSearchInputs()
      self._RenderTemplate(
          'report.html',
          xsrf_token=self.session['xsrf_token'],
          user=self.current_user,
          reporting_form=reporting_form,
          password_generations=password_generations,
          is_admin=self.domain_user_info.get('isAdmin'),
          display_result_message=True,
          download_report_url=self._GenerateDownloadURLForReport(
              reporting_form))

    else:
      _LOG.warning('Reporting form failed validation.  The form data are %s : ',
                   reporting_form.data)
      self._RenderTemplate(
          'report.html',
          xsrf_token=self.session['xsrf_token'],
          user=self.current_user,
          reporting_form=reporting_form,
          is_admin=self.domain_user_info.get('isAdmin'))

  def DownloadReport(self):
    """Generate and serve a report to the requestor."""
    self._InitiatePWG()

    if not self.domain_user_info.get('isAdmin'):
      self._RenderNoAccessIsAllowedErrorPage()

    elif not self.IsXsrfTokenValid(self.current_user,
                                   self.request.get('xsrf_token'),
                                   self.session.get('xsrf_token')):
      self._RenderErrorPage(XSRF_TOKEN_IS_INVALID_LOG_MESSAGE,
                            XSRF_TOKEN_IS_INVALID_ERROR_MESSAGE,
                            self.domain_user_info.get('isAdmin'))

    else:
      report = self._GenerateReportForDownload(
          self._GetPasswordGenerationsBasedOnSearchInputs())

      self.response.headers['X-Frame-Options'] = 'DENY'
      self.response.headers['Content-Type'] = 'text/csv'
      self.response.headers['Content-Disposition'] = ('attachement;'
                                                      'filename=report.csv')
      self.response.headers['Content-Length'] = report.len

      report.seek(0)
      self.response.write(report.read())


class AdminPageHandler(PWGBaseHandler):
  """Handler for the admin page.

  This shows the page where admin can change and update the various settings of
  this service.  This handler will post to itself to do the actual updating and
  then show the result.  The entry point is "/admin".

  Much application logic will use and depend on these setting values. But,
  in order for these setting values to be initially configurable in the
  datastore, the appengine admin is allowed to access and write these settings
  directly to the datastore, i.e. bypass any logic that uses these settings.
  """

  def __init__(self, request, response):
    super(AdminPageHandler, self).__init__(request, response)
    self.SettingsForm = model_form(Setting)  # pylint: disable=g-bad-name

  def _GetEmptySettingsForm(self):
    """Sets default values for admin settings when undefined."""

    create_new_password_message_text = ('To create your Google Apps password '
                                        'please provide a description below.')
    password_created_message_text = 'Your new password is displayed below.'
    error_message_text = ('There was an error. Please contact your '
                          'administrator for assistance.')
    thank_you_message_text = ('Thank you for using Password Generator!! To '
                              'protect your security, you can no longer view '
                              'the password that was generated. If you still '
                              'need your password you will need to generate '
                              'a new one.')

    return self.SettingsForm(
        default_password_length=12,
        private_key_filename='privatekey.pem',
        ios_profile_template_filename='ios_profile_template.xml',
        domain_admin_account='CHANGEME',
        email_body_for_ios_profile_download_notification=
        DEFAULT_EMAIL_BODY_FOR_IOS_PROFILE_DOWNLOAD_NOTIFICATION,
        email_subject_for_ios_profile_download_notification=
        DEFAULT_EMAIL_SUBJECT_FOR_IOS_PROFILE_DOWNLOAD_NOTIFICATION,
        enable_ios_profile_download=None,
        service_account='CHANGEME',
        group_with_access_permission='CHANGEME',
        use_digits_in_password='on',
        use_punctuation_in_password='on',
        use_uppercase_in_password='on',
        remove_ambiguous_characters_in_password='on',
        create_new_password_message=create_new_password_message_text,
        password_created_message=password_created_message_text,
        error_message=error_message_text,
        thank_you_message=thank_you_message_text)

  def _GetSettingsFormPopulatedFromSettingDatastore(self, current_settings):
    return self.SettingsForm(
        default_password_length=current_settings.default_password_length,
        private_key_filename=current_settings.private_key_filename,
        ios_profile_template_filename=
        current_settings.ios_profile_template_filename,
        domain_admin_account=current_settings.domain_admin_account,
        email_body_for_ios_profile_download_notification=
        current_settings.email_body_for_ios_profile_download_notification,
        email_subject_for_ios_profile_download_notification=
        current_settings.email_subject_for_ios_profile_download_notification,
        enable_ios_profile_download=
        current_settings.enable_ios_profile_download,
        service_account=current_settings.service_account,
        group_with_access_permission=
        current_settings.group_with_access_permission,
        use_digits_in_password=current_settings.use_digits_in_password,
        use_punctuation_in_password=
        current_settings.use_punctuation_in_password,
        use_uppercase_in_password=current_settings.use_uppercase_in_password,
        remove_ambiguous_characters_in_password=
        current_settings.remove_ambiguous_characters_in_password,
        create_new_password_message=
        current_settings.create_new_password_message,
        password_created_message=current_settings.password_created_message,
        error_message=current_settings.error_message,
        thank_you_message=current_settings.thank_you_message)

  def _GetEmptySettingsFormOrPopulatedForm(self, current_settings):
    if not current_settings:
      return self._GetEmptySettingsForm()
    else:
      return self._GetSettingsFormPopulatedFromSettingDatastore(
          self.current_settings)

  def _ValidateAndSaveSettingsForm(self, sanitized_settings_form,
                                   sanitized_settings_fields):
    update_is_successful = False
    if sanitized_settings_form.validate():
      _LOG.info('Request to save settings from %s. Saved settings: %s',
                self.current_user.nickname(),
                dict(self.request.POST.items()))
      update_is_successful = Setting.UpdateCurrentSettings(
          sanitized_settings_fields)
      _LOG.debug('Are settings saved successfully for %s: %s',
                 self.current_user.nickname(), update_is_successful)
      self._RenderTemplate(
          'admin.html',
          xsrf_token=self.session.get('xsrf_token'),
          user=self.current_user,
          update_is_successful=update_is_successful,
          visually_ambiguous_char_set=' '.join(VISUALLY_AMBIGUOUS_CHAR_SET),
          punctuation_char_set=' '.join(string.punctuation),
          settings_form=sanitized_settings_form,
          is_admin=True)
    else:
      _LOG.debug('Unable to save settings for %s.  '
                 'Form validation failed for these fields and values:\n%s',
                 self.current_user.nickname(),
                 dict(self.request.POST.items()))
      self._RenderTemplate(
          'admin.html',
          xsrf_token=self.session.get('xsrf_token'),
          user=self.current_user,
          update_is_successful=update_is_successful,
          visually_ambiguous_char_set=' '.join(VISUALLY_AMBIGUOUS_CHAR_SET),
          punctuation_char_set=' '.join(string.punctuation),
          settings_form=sanitized_settings_form,
          is_admin=True)

  def get(self):  # pylint: disable=g-bad-name
    """Get method for AdminPageHandler."""
    self.current_user = users.get_current_user()
    self.session['xsrf_token'] = self.GenerateXsrfToken(self.current_user)

    is_appengine_admin = users.is_current_user_admin()
    if is_appengine_admin:
      _LOG.info(USER_IS_APPENGINE_ADMIN_LOG_MESSAGE,
                self.current_user.nickname())
      self.current_settings = Setting.GetCurrentSettings()
      self._RenderTemplate(
          'admin.html',
          xsrf_token=self.session['xsrf_token'],
          user=self.current_user,
          visually_ambiguous_char_set=' '.join(VISUALLY_AMBIGUOUS_CHAR_SET),
          punctuation_char_set=' '.join(string.punctuation),
          settings_form=self._GetEmptySettingsFormOrPopulatedForm(
              self.current_settings),
          is_admin=is_appengine_admin)
    else:
      self._InitiatePWG()
      if self.domain_user_info['isAdmin']:
        _LOG.info(USER_IS_DOMAIN_ADMIN_LOG_MESSAGE,
                  self.current_user.nickname())
        self._RenderTemplate(
            'admin.html',
            xsrf_token=self.session['xsrf_token'],
            user=self.current_user,
            visually_ambiguous_char_set=' '.join(VISUALLY_AMBIGUOUS_CHAR_SET),
            punctuation_char_set=' '.join(string.punctuation),
            settings_form=self._GetSettingsFormPopulatedFromSettingDatastore(
                self.current_settings),
            is_admin=self.domain_user_info.get('isAdmin'))
      else:
        self._RenderNoAccessIsAllowedErrorPage()

  def post(self):  # pylint: disable=g-bad-name
    """Post method for AdminPageHandler."""

    self.SettingsForm = model_form(
        Setting,
        Form,
        field_args=Setting.GetAdditionalValidators())
    settings_form = self.SettingsForm(self.request.POST)
    sanitized_settings_form, sanitized_settings_fields = (
        self._SanitizeFormAndFields(settings_form))

    self.current_user = users.get_current_user()
    if not self.IsXsrfTokenValid(self.current_user,
                                 self.request.get('xsrf_token'),
                                 self.session.get('xsrf_token')):
      self._RenderErrorPage(XSRF_TOKEN_IS_INVALID_LOG_MESSAGE,
                            XSRF_TOKEN_IS_INVALID_ERROR_MESSAGE,
                            True)
    else:
      is_appengine_admin = users.is_current_user_admin()
      if is_appengine_admin:
        _LOG.info(USER_IS_APPENGINE_ADMIN_LOG_MESSAGE,
                  self.current_user.nickname())
        self._ValidateAndSaveSettingsForm(sanitized_settings_form,
                                          sanitized_settings_fields)
      else:
        self._InitiatePWG()
        if self.domain_user_info['isAdmin']:
          self._ValidateAndSaveSettingsForm(sanitized_settings_form,
                                            sanitized_settings_fields)
        else:
          self._RenderNoAccessIsAllowedErrorPage()


class ThankYouPageHandler(PWGBaseHandler):
  """Handler for the thank you page.

  This is responsible for generating the thank you page, which will be shown to
  users after their passwords have expired.  The entry point is "/thank_you".
  """

  def get(self):  # pylint: disable=g-bad-name
    """Get method for ThankYouPageHandler."""
    self._InitiatePWG()
    self._RenderTemplate(
        'thank_you.html',
        user=self.current_user,
        is_admin=self.domain_user_info.get('isAdmin'),
        thank_you_message=self.current_settings.thank_you_message)


class LandingPageHandler(PWGBaseHandler):
  """Handler to determine which landing page to present to users.

  Take admin users to the admin page.  Otherwise, the request page for others.
  """

  def get(self):  # pylint: disable=g-bad-name
    """Get method for LandingPageHandler."""
    self._InitiatePWG()
    if self.domain_user_info.get('isAdmin'):
      return self.redirect(ADMIN_PAGE_BASE_URL)
    else:
      return self.redirect('/request')


class DeleteExpiredPasswordsHandler(PWGBaseHandler):
  """Handler for cron service to delete expired passwords."""

  def get(self):
    """Get method for DeleteExpiredPasswordsHandler."""
    _LOG.debug('Start deleting expired passwords.')
    for expired_password_entity in PasswordKeeper.GetExpiredPasswords():
      email = expired_password_entity.key.id()
      last_updated_time = expired_password_entity.date.strftime(
          '%m-%d-%Y %H:%M:%S')
      expired_password_entity.key.delete()
      _LOG.debug('Expired password for %s has been deleted.  Its last '
                 'update was at %s.', email, last_updated_time)
    _LOG.debug('Finished deleting expired passwords.')


class DeleteExpiredSessionsHandler(PWGBaseHandler):
  """Handler for cron service to delete expired sessions."""

  def get(self):
    """Get method for DeleteExpiredSessionsHandler."""
    _LOG.debug('Start deleting expired sessions.')
    ndb.delete_multi(Session.GetExpiredSessionKeys())
    _LOG.debug('Finished deleting expired sessions.')


def GetWebapp2ConfigSecretKey():
  """Get the webapp2 config secret key.

  Blaze test will throw AssertionError: No api proxy found for service
  "memcache".  So, just fake a dummy value for testing.

  Returns:
    A string of secret key.
  """
  try:
    return Webapp2SecretKey.GetSecretKey()
  except AttributeError:
    Webapp2SecretKey.UpdateSecretKey()
    return Webapp2SecretKey.GetSecretKey()
  except AssertionError:
    return os.urandom(16).encode('hex')


config = {}
config['webapp2_extras.sessions'] = {'secret_key': GetWebapp2ConfigSecretKey(),
                                     'cookie_args': {'secure': True}}

application = webapp2.WSGIApplication(
    [(ADMIN_PAGE_BASE_URL, AdminPageHandler),
     ('/delete_expired_passwords', DeleteExpiredPasswordsHandler),
     ('/delete_expired_sessions', DeleteExpiredSessionsHandler),
     ('/reporting', ReportPageHandler),
     ('/request', RequestPageHandler),
     ('/result', ResultPageHandler),
     ('/thank_you', ThankYouPageHandler),
     webapp2.Route(DOWNLOAD_IOS_PROFILE_BASE_URL,
                   handler=ResultPageHandler,
                   handler_method='DownloadIOSProfile'),
     webapp2.Route(DOWNLOAD_REPORT_BASE_URL,
                   handler=ReportPageHandler,
                   handler_method='DownloadReport'),
     ('/', LandingPageHandler)],
    debug=False, config=config)
application.error_handlers[401] = Handle401
