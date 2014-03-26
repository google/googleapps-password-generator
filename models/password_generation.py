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

"""Models an individual password generation entity in appengine datastore."""

import cgi
import logging

from password_generation_history import PasswordGenerationHistory

from google.appengine.ext import ndb

_LOG = logging.getLogger('google_password_generator.password_generation')


class PasswordGeneration(ndb.Model):
  """Models an individual password generation entity in appengine datastore.

  This will be used for tracking each attempt by users to generate new
  passwords or download the ios profile.
  """

  user = ndb.UserProperty(required=True)
  date = ndb.DateTimeProperty(auto_now_add=True, required=True)
  reason = ndb.StringProperty(required=True)
  user_agent = ndb.StringProperty()
  user_ip_address = ndb.StringProperty()
  password_length = ndb.IntegerProperty()
  are_digits_used_for_password = ndb.StringProperty()
  is_punctuation_used_for_password = ndb.StringProperty()
  is_uppercase_used_for_password = ndb.StringProperty()

  @staticmethod
  def GetPasswordGenerationsByDate(start_datetime, end_datetime):
    """Get the password generations for the specified date range.

    Args:
      start_datetime: datetime object of the starting date to query
      end_datetime: datetime object of the ending date to query

    Returns:
      query result as a list containing password generation objects
    """
    return PasswordGeneration.gql(
        'WHERE date >= :1 and date <= :2 ORDER BY date DESC',
        start_datetime, end_datetime).fetch()

  @staticmethod
  def GetPasswordGenerationsByUser(user):
    """Get the password generations for the specified user.

    Args:
      user: appengine user object

    Returns:
      query result as a list containing password generation objects
    """
    return PasswordGeneration.gql(
        'WHERE user = :1 ORDER BY date DESC', user).fetch()

  @staticmethod
  def GetPasswordGenerationsByDateAndUser(start_datetime, end_datetime, user):
    """Get the password generations for the specified date range and user.

    Args:
      start_datetime: datetime object of the starting date to query
      end_datetime: datetime object of the ending date to query
      user: appengine user object

    Returns:
      query result as a list containing password generation objects
    """
    return PasswordGeneration.gql(
        'WHERE date >= :1 AND date <= :2 AND user = :3 ORDER BY date DESC',
        start_datetime, end_datetime, user).fetch()

  @staticmethod
  def StorePasswordGeneration(user, reason, user_agent, remote_addr,
                              password_length, use_digits_in_password,
                              use_punctuation_in_password,
                              use_uppercase_in_password):
    """Store the attempt to generate a password which can be used for reporting.

    We set a parent key for the 'Password Generation' to ensure that they are
    all in the same entity group. This way, queries across the single
    entity group will be consistent.

    Args:
      user: appengine user object
      reason: string of the reason for generating the password
      user_agent: string of the browser user-agent
      remote_addr: string of the remote user's ip address
      password_length: integer of the password length
      use_digits_in_password: string of 'on' or 'off'
      use_punctuation_in_password: string of 'on' or 'off'
      use_uppercase_in_password: string of 'on' or 'off'
    """
    password_generation = PasswordGeneration(
        parent=PasswordGenerationHistory.GetKey())
    password_generation.user = user
    password_generation.reason = reason
    password_generation.user_agent = user_agent
    password_generation.user_ip_address = remote_addr
    password_generation.password_length = password_length
    password_generation.are_digits_used_for_password = use_digits_in_password
    password_generation.is_punctuation_used_for_password = (
        use_punctuation_in_password)
    password_generation.is_uppercase_used_for_password = (
        use_uppercase_in_password)
    password_generation.put()
    _LOG.info('Successfully logged password generation attempt.')
    _LOG.debug('The logged password generation is: %s', password_generation)

  @staticmethod
  def StoreIOSProfileDownloadEvent(user, user_agent, remote_addr):
    """Store the attempt to download ios profile for reporting.

    We set a parent key for the 'Password Generation' to ensure that they are
    all in the same entity group. This way, queries across the single
    entity group will be consistent.

    Args:
      user: appengine user object
      user_agent: string of the browser user-agent
      remote_addr: string of the remote user's ip address
    """
    ios_profile_download = PasswordGeneration(
        parent=PasswordGenerationHistory.GetKey())
    ios_profile_download.user = user
    ios_profile_download.reason = 'Download IOS Profile'
    ios_profile_download.user_agent = user_agent
    ios_profile_download.user_ip_address = remote_addr
    ios_profile_download.password_length = None
    ios_profile_download.are_digits_used_for_password = None
    ios_profile_download.is_punctuation_used_for_password = None
    ios_profile_download.is_uppercase_used_for_password = None
    ios_profile_download.put()
    _LOG.info('Successfully logged ios profile download attempt.')
    _LOG.debug('The logged ios_profile_download is: %s', ios_profile_download)
