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

"""Model for the secret key used to configure the webapp2."""

import logging
import os

from google.appengine.ext import ndb

_LOG = logging.getLogger('google_password_generator.webapp2_secret_key')


class Webapp2SecretKey(ndb.Model):
  """Model for the secret key used to configure the webapp2.

  There should be only one setting entity, with an id of current_secret_key.
  This also means that this setting entity is a root entity, without any parent.
  """
  secret_key = ndb.StringProperty()

  @staticmethod
  def GetSecretKey():
    """Get webapp2 secret key.

    Returns:
      A string of the webapp2 secret key.
    """
    _LOG.info('Getting webapp2_secret_key.')
    return (Webapp2SecretKey.get_by_id('current_secret_key')
            .secret_key.encode('ascii', 'ignore'))

  @staticmethod
  def UpdateSecretKey():
    """Update the webapp2 secret key.

    Returns:
      boolean, true if update has completed successfully
    """
    _LOG.info('Updating webapp2_secret_key.')
    webapp2_secret_key = Webapp2SecretKey(id='current_secret_key')
    webapp2_secret_key.secret_key = os.urandom(16).encode('hex')
    webapp2_secret_key.put()
    return True
