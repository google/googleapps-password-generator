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

"""A helper class to wrangle the xsrf utilities, and provide more logging."""

import logging

from oauth2client import appengine
from oauth2client import xsrfutil

_LOG = logging.getLogger('google_password_generator.xsrf_helper')


class XsrfHelper(object):
  """A helper class to wrangle the xsrf utilities, and provide more logging."""

  def GenerateXsrfToken(self, current_user):
    """Generate a xsrf token.

    Args:
      current_user: Appengine user object of the current user.

    Returns:
      A string of the xsrf token.
    """
    _LOG.info('Generating xsrf token for %s.', current_user.nickname())
    xsrf_token = xsrfutil.generate_token(appengine.xsrf_secret_key(),
                                         current_user.user_id())
    _LOG.debug('Successfully generated xsrf token for %s.',
               current_user.nickname())
    return xsrf_token

  def _IsXsrfTokenWellFormedAndNotExpired(self, current_user, xsrf_token):
    """Determine if the submitted xsrf token is well-formed and has not expired.

    By well-formed, we mean if the the submitted xsrf token can be decoded and
    will match the generated xsrf token using the same criteria (i.e. check
    forgery).

    Args:
      current_user: Appengine user object of the current user.
      xsrf_token: A string of the xsrf token.

    Returns:
      A boolean, true if the token is well-formed and has not expired.
          Otherwise, false.
    """
    is_xsrf_token_well_formed_and_not_expired = xsrfutil.validate_token(
        appengine.xsrf_secret_key(), xsrf_token, current_user.user_id())
    _LOG.debug('Is xsrf token well-formed and not expired for %s: %s',
               current_user.nickname(),
               is_xsrf_token_well_formed_and_not_expired)
    return is_xsrf_token_well_formed_and_not_expired

  def _IsSubmittedXsrfTokenMatchingWithSessionXsrfToken(self,
                                                        current_user,
                                                        submitted_xsrf_token,
                                                        session_xsrf_token):
    """Determine if the submitted xsrf token matches the xsrf token in session.

    Args:
      current_user: Appengine user object of the current user.
      submitted_xsrf_token: A string of the submitted xsrf token.
      session_xsrf_token: A string of the xsrf token stored in user session.

    Returns:
      A boolean, true if submitted xsrf token matches the xsrf token in session.
          Otherwise, false.
    """
    if submitted_xsrf_token == session_xsrf_token:
      _LOG.debug('Submitted xsrf token matches the session xsrf token for %s.',
                 current_user.nickname())
      return True
    else:
      _LOG.debug('Submitted xsrf token does not match the session xsrf token '
                 'for %s.', current_user.nickname())
      return False

  def IsXsrfTokenValid(self, current_user, submitted_xsrf_token,
                       session_xsrf_token):
    """Performs various checks to see if the submitted xsrf token is valid.

    Args:
      current_user: Appengine user object of the current user.
      submitted_xsrf_token: A string of the submitted xsrf token.
      session_xsrf_token: A string of the xsrf token stored in user session.

    Returns:
      A boolean, true if submitted xsrf token is valid.  Otherwise, false.
    """
    _LOG.info('Checking if xsrf token is valid for %s.',
              current_user.nickname())
    return (self._IsXsrfTokenWellFormedAndNotExpired(current_user,
                                                     submitted_xsrf_token)
            and self._IsSubmittedXsrfTokenMatchingWithSessionXsrfToken(
                current_user, submitted_xsrf_token, session_xsrf_token))
