/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/**
 * @fileoverview JS for the admin.html, i.e. admin console for settings.
 */


/**
 * Create a successful notification (noty).
 */
function PWG_GenerateSuccessfulNoty() {
  noty({
    text: 'Settings saved.',
    type: 'warning',
    layout: 'topCenter',
    closeWith: ['button'],
    timeout: 3000
  });
}


/**
 * Create a unsuccessful notification (noty).
 */
function PWG_GenerateUnsuccessfulNoty() {
  noty({
    text: 'Error saving settings.',
    type: 'error',
    layout: 'topCenter',
    closeWith: ['button'],
    timeout: 3000
  });
}
