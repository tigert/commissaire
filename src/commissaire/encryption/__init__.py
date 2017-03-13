# Copyright (C) 2017  Red Hat, Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Encryption related classes.
"""

import base64


class EncryptionBase:
    """
    Encryption base class.
    """

    def _b64decode(self, data):
        """
        Decodes data.

        :param data: The data to decode
        :type data: str or bytes
        :returns: bytes
        """
        if type(data) is str:
            data = data.encode()

        try:
            return base64.decodebytes(data)
        except base64.binascii.Error:
            # Not base64 encoded
            return data

    def _b64encode(self, data):
        """
        Encodes data.

        :param data: The data to decode
        :type data: str or bytes
        :returns: bytes
        """
        if type(data) is str:
            data = data.encode()

        return base64.encodebytes(data)

    def encrypt(self, data, *args, **kwargs):
        """
        Encrypts, base64 encodes, and returns the encrypted data.

        :param data: The data to decrypt
        :type data: str or unicode
        :param args: All other non-keyword arguments
        :type args: list
        :param kwargs: All other keyword arguments
        :type kwargs: dict
        :returns: str or unicode
        """
        return self._b64encode(self._encrypt(
            data, *args, **kwargs)).decode('utf-8')

    def _encrypt(self, data, *args, **kwargs):
        """
        Encryption implementation.

        :param data: The data to decrypt
        :type data: str or unicode
        :param args: All other non-keyword arguments
        :type args: list
        :param kwargs: All other keyword arguments
        :type kwargs: dict
        :returns: bytes
        """
        raise NotImplementedError('_encrypt must be overriden')

    def decrypt(self, data, *args, **kwargs):
        """
        Decrypts, decodes, and returns the original data.

        :param data: The data to decrypt
        :type data: str or unicode
        :param args: All other non-keyword arguments
        :type args: list
        :param kwargs: All other keyword arguments
        :type kwargs: dict
        :returns: str or unicode
        """
        data = self._b64decode(data)
        return self._decrypt(
            data, *args, **kwargs).decode('utf-8')

    def _decrypt(self, data, *args, **kwargs):
        """
        Decryption implementation.

        :param data: The data to decrypt
        :type data: str or unicode
        :param args: All other non-keyword arguments
        :type args: list
        :param kwargs: All other keyword arguments
        :type kwargs: dict
        :returns: bytes
        """
        raise NotImplementedError('_decrypt must be overriden')


class GNUPGEncryption(EncryptionBase):
    """
    gnupg encryption implementation. If there are no keys already configured
    this class will generate a new key with the name based on the
    initialization input.
    """

    #: The gnupg module
    import gnupg

    def __init__(self, name, passphrase,
                 keydir='/etc/commissaire/gpg', verbose=False):
        """
        Initializes a new instance of the GNUPG Encryption class.

        :param passphrase: The password to use when decrypting.
        :type passphrase: str
        :param name: "Real name" of the key. Used to find generated keys.
        :type name: str
        :param keydir: Full path to where the key data will be stored.
        :type keydir: str
        :param verbose: If the encryptor should be verbose (default: False)
        :type verbose: bool
        """
        self.__passphrase = passphrase
        self._encryptor = self.gnupg.GPG(
            homedir=keydir,
            verbose=verbose)

        # Use the key if it exists
        self.fingerprint = None
        for keydata in self._encryptor.list_keys():
            for uid in keydata['uids']:
                if uid.split(' ')[0].lower() == name.lower():
                    self.fingerprint = keydata['fingerprint']
                    break

        # Else make one
        if not self.fingerprint:
            key_settings = self._encryptor.gen_key_input(
                key_type='RSA',
                key_length=2048,
                key_usage='ESCA',
                name_real=name,
                passphrase=self.__passphrase)
            key = self._encryptor.gen_key(key_settings)
            self.fingerprint = key.fingerprint

    def _encrypt(self, data):
        """
        GNUPG Encryption implementation.

        :param data: The data to decrypt
        :type data: str or unicode
        :returns: bytes
        """
        return self._encryptor.encrypt(data, self.fingerprint).data

    def _decrypt(self, data, *args, **kwargs):
        """
        GNUPG decryption implementation.

        :param data: The data to decrypt
        :type data: str or unicode
        :returns: bytes
        """
        return self._encryptor.decrypt(
            data, passphrase=self.__passphrase).data
