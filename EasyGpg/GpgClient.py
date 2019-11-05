import pgpy
import traceback
import warnings


# noinspection PyMethodMayBeStatic
class GpgClient:
    # Set encryption algorithm
    def __init__(
            self,
            key_files=None,
            key_blobs=None,
            log_level=1
    ):
        """
        Setup GPG encryption client

        :type key_files: dict
        :param key_files: Dictionary of key files

        :type key_blobs: dict
        :param key_blobs: Dictionary of key blobs

        :type log_level: int
        :param log_level: Debugging log level
        """
        self.keys = {}
        self.log_level = log_level

        # If a dictionary of key filenames was passed, load them now
        if key_files is not None:
            self.log_trace('Loading key files...')
            self.load_key_files(key_files)

        # If a dictionary of key blobs was passed, load them now
        if key_blobs is not None:
            self.log_trace('Loading key blobs...')
            self.load_key_blobs(key_blobs)

    # Load an individual key from a blob
    def load_key_blob(self, name, blob):
        # Parse the key contents
        key, _ = pgpy.PGPKey.from_blob(blob)
        self.log_trace('Loading key blob: {name}...'.format(name=name))
        self.keys[name] = key

    # Load an individual key from a file
    def load_key_file(self, name, filename):
        self.log_trace('Loading key file: {filename}...'.format(filename=filename))
        key, _ = pgpy.PGPKey.from_file(filename)
        self.keys[name] = key

    # Load multiple keys from a dictionary of files
    def load_key_files(self, filenames):
        self.log_trace('Loading key files...')
        for name, filename in filenames.items():
            self.log_trace('Loading key file: {name}...'.format(name=name))
            key, _ = pgpy.PGPKey.from_file(filename)
            self.keys[name] = key

    # Load multiple keys from a dictionary of blobs
    def load_key_blobs(self, blobs):
        self.log_trace('Loading key blobs...')
        for name, blob in blobs.items():
            self.log_trace('Loading key blob: {name}...'.format(name=name))
            key, _ = pgpy.PGPKey.from_blob(blob)
            self.keys[name] = key

    # Delete all previously loaded keys
    def clear_keys(self):
        self.log_trace('Clearing keys...')
        self.keys = {}

    # Delete an individual key by name
    def delete_key(self, name):
        self.log_trace('Deleting key: {name}'.format(name=name))
        self.log_trace('Searching for key...')
        if name in self.keys:
            self.log_trace('Key found, removing...')
            self.keys.pop(name, None)
        else:
            self.log_trace('Key not found')

    # Sign the supplied plain text
    def sign(
            self,
            plain_text,
            signing_key,
            compression=pgpy.constants.CompressionAlgorithm.Uncompressed,
            encoding=None
    ):
        self.log_trace('Signing message...')
        # Retrieve the public key from storage
        signing_key = self.keys[signing_key]

        # The encryption library will generate a warning about the key being used not being able to encrypt/decrypt
        # a message, and that it will try (and succeed) to use a sub-key. To prevent this flooding CloudWatch
        # unnecessarily, we will suppress this specific warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # Create a PGP message containing the unencrypted text
            self.log_trace('Creating PGP message...')
            message_unencrypted = pgpy.PGPMessage.new(
                message=plain_text,
                encoding=encoding,
                compression=compression
            )

            # Sign the message by logically or'ing with signature
            self.log_trace('Signing PGP message...')
            message_signed = message_unencrypted | signing_key.sign(subject=message_unencrypted)

            # If we did receive a warning ensure it is only the one about using the the sub-key
            if -1 in w:
                if issubclass(w[-1].category, UserWarning):
                    assert 'does not have the required usage flag' in str(w[-1].message)
                    assert 'EncryptStorage, EncryptCommunications; using subkey' in str(w[-1].message)

            # Turn warnings back on
            warnings.simplefilter('default')

        # Return the encrypted message
        self.log_trace('Returning message...')
        return message_signed

    # Sign the supplied plain text then encrypt it
    def sign_and_encrypt(
            self,
            plain_text,
            encryption_key,
            signing_key,
            compression=pgpy.constants.CompressionAlgorithm.Uncompressed,
            cipher=pgpy.constants.SymmetricKeyAlgorithm.AES256,
            encoding=None
    ):
        self.log_trace('Signing and encrypting message...')

        # Retrieve the public key from storage
        self.log_trace('Retrieving encryption key...')
        encryption_key = self.keys[encryption_key]

        # The encryption library will generate a warning about the key being used not being able to encrypt/decrypt
        # a message, and that it will try (and succeed) to use a sub-key. To prevent this flooding CloudWatch
        # unnecessarily, we will suppress this specific warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # Create a signed message from the supplied text
            self.log_trace('Signing message...')
            message_signed = self.sign(
                plain_text=plain_text,
                signing_key=signing_key,
                compression=compression,
                encoding=encoding
            )

            # Encrypt the signed message
            self.log_trace('Encrypting signed message...')
            message_encrypted = encryption_key.encrypt(
                message=message_signed,
                cipher=cipher
            )

            # If we did receive a warning ensure it is only the one about using the the sub-key
            if -1 in w:
                if issubclass(w[-1].category, UserWarning):
                    assert 'does not have the required usage flag' in str(w[-1].message)
                    assert 'EncryptStorage, EncryptCommunications; using subkey' in str(w[-1].message)

            # Turn warnings back on
            warnings.simplefilter('default')

        # Return the encrypted message
        self.log_trace('Returning message...')
        return message_encrypted

    # Decrypt the supplied cipher text (or encrypted PHP message)
    def decrypt(self, cipher_text, key_name):
        # Retrieve the private key from storage
        self.log_trace('Retrieving decryption key...')
        private_key = self.keys[key_name]

        # The encryption library will generate a warning about the key being used not being able to encrypt/decrypt
        # a message, and that it will try (and succeed) to use a sub-key. To prevent this flooding CloudWatch
        # unnecessarily, we will suppress this specific warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            # Create a PGP message from the cipher text
            pgp_message_encrypted = pgpy.PGPMessage.from_blob(str(cipher_text))

            # Decrypt the message
            self.log_trace('Decrypting message...')
            pgp_message_unencrypted = private_key.decrypt(pgp_message_encrypted)

            # If we did receive a warning ensure it is only the one about using the the sub-key
            if -1 in w:
                if issubclass(w[-1].category, UserWarning):
                    assert 'Message was encrypted with this key\'s subkey' in str(w[-1].message)
                    assert 'Decrypting with that' in str(w[-1].message)

            # Turn warnings back on
            warnings.simplefilter('default')

        # Return the unencrypted message
        self.log_trace('Returning message...')
        return pgp_message_unencrypted.message

    # Decrypt the supplied cipher text (or encrypted PHP message)
    def verify(self, cipher_text, signing_key_name):
        # Retrieve the required keys from storage
        self.log_trace('Retrieving signing key...')
        public_key = self.keys[signing_key_name]

        # The encryption library will generate a warning about the key being used not being able to encrypt/decrypt
        # a message, and that it will try (and succeed) to use a sub-key. To prevent this flooding CloudWatch
        # unnecessarily, we will suppress this specific warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            # Create a PGP message from the cipher text
            self.log_trace('Creating PGP message...')
            pgp_message_encrypted = pgpy.PGPMessage.from_blob(str(cipher_text))

            self.log_trace('Verifying signature...')
            signature = public_key.verify(pgp_message_encrypted)

            # If we did receive a warning ensure it is only the one about using the the sub-key
            if -1 in w:
                if issubclass(w[-1].category, UserWarning):
                    assert 'Message was encrypted with this key\'s subkey' in str(w[-1].message)
                    assert 'Decrypting with that' in str(w[-1].message)

            # Turn warnings back on
            warnings.simplefilter('default')

        # Return the unencrypted message
        self.log_trace('Returning signature...')
        return signature

    # Logging Functions

    def log(self, message):
        """
        Print standard log message

        :param message: Message to print
        :type message: str/Exception

        :return: None
        """
        print('[EasySftpServer.py] {message}'.format(message=message))

    def log_error(self, message):
        """
        Print error log message

        :param message: Message to print
        :type message: str/Exception

        :return: None
        """
        print('ERROR [EasySftpServer.py] {message}'.format(message=message))

    def log_warning(self, message):
        """
        Print warning log message

        :param message: Message to print
        :type message: str/Exception

        :return: None
        """
        if self.log_level >= 1:
            print('WARNING [EasySftpServer.py] {message}'.format(message=message))

    def log_debug(self, message):
        """
        Print debugging log message only if the global value 'debug_logging' is set to True

        :param message: Message to print
        :type message: str/Exception

        :return: None
        """
        if self.log_level >= 2:
            print('DEBUG [EasySftpServer.py] {message}'.format(message=message))

    def log_trace(self, message):
        """
        Print debugging log message only if the global value 'debug_logging' is set to True

        :param message: Message to print
        :type message: str/Exception

        :return: None
        """
        if self.log_level >= 3:
            print('TRACE [EasySftpServer.py] {message}'.format(message=message))

    def exit_fatal_error(self, message):
        """
        Terminate execution after logging a fatal error message, reports error code 911 and adds a CloudWatch
        fatal error metric count

        :return: None
        """
        # Log error
        print('FATAL ERROR [EasySftpServer.py] {message}'.format(message=message))

        # Print stack trace
        for line in traceback.format_stack():
            print(line.strip())

        # Terminator process with 911 error code
        exit(911)
