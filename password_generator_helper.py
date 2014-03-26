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

"""A helper class for the application logic used for password generator."""

import cgi


class PasswordGeneratorHelper(object):
  """A helper class for the application logic used for password generator."""

  @staticmethod
  def SanitizeText(text):
    """Sanitized a string and return it.

    Args:
      text: a string

    Returns:
      A sanitized string.
    """
    return cgi.escape(text.strip(), quote=True)

  @staticmethod
  def IsIOSDevice(user_agent):
    """Determine if user_agent indicates iOS device.

    Args:
      user_agent: string of the user_agent

    Returns:
      True if user agent indicates ios device, or false otherwise.
    """
    return 'iPhone' in user_agent or 'iPad' in user_agent

  @staticmethod
  def IsSafariBrowser(user_agent):
    """Determine if user_agent indicates Safari browser.

    Args:
      user_agent: string of the user_agent

    Returns:
      True if user agent indicates safari browser, or false otherwise.
    """
    return 'Safari' in user_agent
