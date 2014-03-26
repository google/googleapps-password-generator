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

"""Models the webapp2 session entity in appengine datastore."""

from datetime import datetime
from datetime import timedelta
import logging

from google.appengine.ext import ndb

_LOG = logging.getLogger('google_password_generator.session')


class Session(ndb.Model):
  """Models the webapp2 session entity in appengine datastore.

  The reason to model the entity is for query formation.

  A key information in the session data is the xsrf_token.
  """
  data = ndb.BlobProperty(required=True)
  updated = ndb.DateTimeProperty(auto_now=True, required=True)

  @staticmethod
  def GetExpiredSessionKeys():
    """Get the keys of the sessions that meet the expiration criteria.

    The keys will be used to perform bulk deletion.

    Returns:
      query result as a list containing session entity keys
    """
    cutoff_time_for_expired_sessions = (
        datetime.utcnow() - timedelta(hours=24))
    _LOG.debug('The cutoff time for sessions to be expired is: %s',
               cutoff_time_for_expired_sessions.strftime('%m-%d-%Y %H:%M:%S'))
    return Session.gql('WHERE updated <= :1',
                       cutoff_time_for_expired_sessions).fetch(keys_only=True)
