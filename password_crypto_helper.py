"""A helper class to encrypt and decrypt passwords.

Example and documentation provided at the link below is pre-req for
understanding this helper.

https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html

Some key points from the documentation:

The block size determines the AES key size:
16 (AES-128), 24 (AES-192), or 32 (AES-256)

MODE_CFB is chosen as the chaining mode, because it is recommended by the
documentation and example is provided.  crypto_initialization_vector is
required for this mode.  Otherwise, as a counter-example, the simpliest
MODE_ECB doesn't need the crypto_initialization_vector, but it is deemed not
as strong.

https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.blockalgo-module.html#MODE_CFB
https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.blockalgo-module.html#MODE_ECB

The pycrypto cipher will handle the actual encryption and decryption processes.

https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES.AESCipher-class.html
"""

import logging
import os

from Crypto.Cipher import AES


_LOG = logging.getLogger('google_password_generator.password_crypto_helper')

BLOCK_SIZE = 16


class PasswordCryptoHelper(object):
  """A helper class to encrypt and decrypt passwords.

  The basic premise of how this helper works is that the password will be
  encrypted for storage, and can be retrieved later for decryption, based on
  the AES-128 standard.

  So, for the purpose of decryption, a password_key will be generated.  This
  will be passed to the user, which will require the password_key to be
  encoded as base-64 strings.  Later for decryption, the password_key will be
  passed back by the user, decoded back from string, and used by the cipher to
  decrypt the encrypted password.

  Because the crypto_initialization_vector is needed by the cipher, it will
  also be returned, so that it can be stored alongside the encrypted
  password.  Then, it will also be retrieved later alongside the encrypted
  password so that it can be used by the cipher for decryption.
  """

  @staticmethod
  def EncryptPassword(password):
    """Encrypt password.

    Args:
      password: a string of the password to be encrypted

    Returns:
      Byte string of the encrypted password, string of the password key, and
          byte string of the crypto initialization vector.
    """
    password_key = os.urandom(BLOCK_SIZE)
    crypto_initialization_vector = os.urandom(BLOCK_SIZE)
    cipher = AES.new(password_key, AES.MODE_CFB, crypto_initialization_vector)
    encrypted_password = cipher.encrypt(password)
    _LOG.debug('Successfully encrypted password.')
    return (encrypted_password, password_key.encode('base-64'),
            crypto_initialization_vector)

  @staticmethod
  def DecryptPassword(encrypted_password_entity, password_key):
    """Decrypt password.

    Args:
      encrypted_password_entity: datastore entity of the encrypted password
      password_key: string of the password key

    Returns:
      decrypted_password: string of the decrypted password
    """
    cipher = AES.new(password_key.decode('base-64'), AES.MODE_CFB,
                     encrypted_password_entity.crypto_initialization_vector)
    decrypted_password = cipher.decrypt(
        encrypted_password_entity.encrypted_password)
    _LOG.debug('Successfully decrypted password.')
    return decrypted_password
