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
 * @fileoverview JS for the result.html page.
 */


/**
 * Fade out and hide the password, after initial page load.
 */
$(function() {
  $('#password').delay(60000).fadeOut('slow', function() {
    PWG_HidePassword($('#password').text());
  });
  setTimeout(PWG_ExpirePassword, 300000);
});


/**
 * Hide the password, and show a reveal button.
 * @param {!string} password The newly generated password.
 */
function PWG_HidePassword(password) {
  var hidden_password = '';
  for (var i = 0; i < password.length; i++) {
    hidden_password += '*';
  }
  $('#password').html(hidden_password).fadeIn('fast');
  $('#reveal_password_button').css('visibility', 'visible');
}


/**
 * Hide the reveal button, and reveal the password.
 * @param {!string} password The newly generated password.
 */
function PWG_RevealPassword(password) {
  $('#reveal_password_button').css('visibility', 'hidden');
  $('#password').html(password).fadeIn('fast').delay(60000)
      .fadeOut('slow', function() {
        PWG_HidePassword(password);
      });
}


/**
 * Expires the displayed password, so that user can not see or access it.
 */
function PWG_ExpirePassword() {
  window.location.replace('/thank_you');
}
