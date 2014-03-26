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

"""Models individual setting values used to configure the application."""

import logging

from wtforms import validators

from google.appengine.ext import ndb

_LOG = logging.getLogger('google_password_generator.setting')


class Setting(ndb.Model):
  """Models the setting values used to configure the application.

  Each setting value would be in a field.

  There should be only one setting entity, with an id of current_settings.
  This also means that this setting entity is a root entity, without any parent.
  """
  create_new_password_message = ndb.StringProperty(required=True)
  default_password_length = ndb.IntegerProperty(required=True)
  domain_admin_account = ndb.StringProperty(required=True)
  email_body_for_ios_profile_download_notification = (
      ndb.StringProperty(required=True))
  email_subject_for_ios_profile_download_notification = (
      ndb.StringProperty(required=True))
  enable_ios_profile_download = ndb.StringProperty()
  error_message = ndb.StringProperty(required=True)
  group_with_access_permission = ndb.StringProperty(required=True)
  ios_profile_template_filename = ndb.StringProperty(required=True)
  password_created_message = ndb.StringProperty(required=True)
  private_key_filename = ndb.StringProperty(required=True)
  remove_ambiguous_characters_in_password = ndb.StringProperty()
  service_account = ndb.StringProperty(required=True)
  thank_you_message = ndb.StringProperty(required=True)
  use_digits_in_password = ndb.StringProperty()
  use_punctuation_in_password = ndb.StringProperty()
  use_uppercase_in_password = ndb.StringProperty()

  @staticmethod
  def GetCurrentSettings():
    """Return a setting entity, specifically the current_settings."""
    return Setting.get_by_id('current_settings')

  @staticmethod
  def UpdateCurrentSettings(new_settings):
    """Update values for all setting entities.

    Note about checkbox form elements:
    Checkbox form elements are submitted in the form with a value of 'on'.
    They're left out of the post when they're unchecked, so the boolean value
    in the data store should be 'off'.
    See more: http://www.w3.org/TR/html401/interact/forms.html#h-17.2.1

    Args:
      new_settings: a dictionary of the new settings to be updated

    Returns:
      boolean, true if update has completed successfully
    """
    current_settings = Setting(id='current_settings')
    current_settings.create_new_password_message = new_settings[
        'create_new_password_message']
    current_settings.default_password_length = int(new_settings[
        'default_password_length'])
    current_settings.domain_admin_account = new_settings[
        'domain_admin_account']

    if not new_settings['enable_ios_profile_download']:
      new_settings['enable_ios_profile_download'] = 'off'
    current_settings.enable_ios_profile_download = new_settings.get(
        'enable_ios_profile_download')

    current_settings.email_subject_for_ios_profile_download_notification = (
        new_settings.get('email_subject_for_ios_profile_download_notification'))
    current_settings.email_body_for_ios_profile_download_notification = (
        new_settings.get('email_body_for_ios_profile_download_notification'))

    current_settings.error_message = new_settings['error_message']
    current_settings.group_with_access_permission = new_settings[
        'group_with_access_permission']
    current_settings.ios_profile_template_filename = new_settings[
        'ios_profile_template_filename']
    current_settings.password_created_message = new_settings[
        'password_created_message']
    current_settings.private_key_filename = new_settings[
        'private_key_filename']

    if not new_settings['remove_ambiguous_characters_in_password']:
      new_settings['remove_ambiguous_characters_in_password'] = 'off'
    current_settings.remove_ambiguous_characters_in_password = new_settings.get(
        'remove_ambiguous_characters_in_password')

    current_settings.service_account = new_settings['service_account']
    current_settings.thank_you_message = new_settings['thank_you_message']

    if not new_settings['use_digits_in_password']:
      new_settings['use_digits_in_password'] = 'off'
    current_settings.use_digits_in_password = new_settings.get(
        'use_digits_in_password')

    if not new_settings['use_punctuation_in_password']:
      new_settings['use_punctuation_in_password'] = 'off'
    current_settings.use_punctuation_in_password = new_settings.get(
        'use_punctuation_in_password')

    if not new_settings['use_uppercase_in_password']:
      new_settings['use_uppercase_in_password'] = 'off'
    current_settings.use_uppercase_in_password = new_settings.get(
        'use_uppercase_in_password')

    current_settings.put()
    return True

  @staticmethod
  def GetAdditionalValidators():
    """Get additional wtforms validators that we can use on the server-side."""
    return {
        'default_password_length': {
            'validators': [validators.NumberRange(min=8, max=20)]
        },
        'domain_admin_account': {
            'validators': [validators.Email()]
        },
        'group_with_access_permission': {
            'validators': [validators.Email()]
        },
        'service_account': {
            'validators': [validators.Email()]
        }
    }
