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

"""Models password generation history entity in appengine datastore."""

from google.appengine.ext import ndb


class PasswordGenerationHistory(ndb.Model):
  """The parent entity for Password Generation.

  See _LogPasswordGeneration() why we need this, and how it is used.
  """

  @staticmethod
  def GetKey():
    """Return a datastore key for password generation history entity."""
    return ndb.Key('PasswordGenerationHistory', 'password_generation_history')
