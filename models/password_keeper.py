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

"""Models the encrypted password entity in appengine datastore."""

from datetime import datetime
from datetime import timedelta
import logging

from google.appengine.ext import ndb

_LOG = logging.getLogger('google_password_generator.password_keeper')


class PasswordKeeper(ndb.Model):
  """Models the encrypted password entity in appengine datastore.

  This will be used for keeping the encrypted passwords for populating the
  ios profile template for multiple device configurations.
  """
  date = ndb.DateTimeProperty(auto_now=True, required=True)
  encrypted_password = ndb.BlobProperty(required=True)
  crypto_initialization_vector = ndb.BlobProperty(required=True)

  @staticmethod
  def StorePassword(email, encrypted_password, crypto_initialization_vector):
    """Store the encrypted password and crypto info.

    Args:
      email: string of the user email for whom the password is being stored
      encrypted_password: byte string of the encrypted password
      crypto_initialization_vector: byte string of the crypto
          initialization vector
    """
    password_keeper = PasswordKeeper(id=email)
    password_keeper.encrypted_password = encrypted_password
    password_keeper.crypto_initialization_vector = crypto_initialization_vector
    password_keeper.put()
    _LOG.info('Successfully stored encrypted password for %s.', email)

  @staticmethod
  def GetPassword(email):
    """Get the encrypted password for the specified email.

    Args:
      email: string of the user email

    Returns:
      datastore entity of the encrypted password
    """
    return PasswordKeeper.get_by_id(email)

  @staticmethod
  def GetExpiredPasswords():
    """Get the encrypted passwords that meets the expiration criteria.

    Returns:
      query result as a list containing password keeper entities
    """
    cutoff_time_for_expired_passwords = (
        datetime.utcnow() - timedelta(minutes=15))
    _LOG.debug('The cutoff time for passwords to be expired is: %s',
               cutoff_time_for_expired_passwords.strftime('%m-%d-%Y %H:%M:%S'))
    return PasswordKeeper.gql('WHERE date <= :1',
                              cutoff_time_for_expired_passwords).fetch()

