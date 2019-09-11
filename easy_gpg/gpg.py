import pgpy
import warnings


class EncryptionClient:
    # Set encryption algorithm
    def __init__(self, key_files=None, key_blobs=None):
        self.keys = {}

        # If a dictionary of key filenames was passed, load them now
        if key_files is not None:
            self.load_key_files(key_files)

        # If a dictionary of key blobs was passed, load them now
        if key_blobs is not None:
            self.load_key_blobs(key_blobs)

    # Load an individual key from a blob
    def load_key_blob(self, name, blob):
        # Parse the key contents
        key, _ = pgpy.PGPKey.from_blob(blob)
        self.keys[name] = key

    # Load an individual key from a file
    def load_key_file(self, name, filename):
        key, _ = pgpy.PGPKey.from_file(filename)
        self.keys[name] = key

    # Load multiple keys from a dictionary of files
    def load_key_files(self, filenames):
        for name, filename in filenames.items():
            key, _ = pgpy.PGPKey.from_file(filename)
            self.keys[name] = key

    # Load multiple keys from a dictionary of blobs
    def load_key_blobs(self, blobs):
        for name, blob in blobs.items():
            key, _ = pgpy.PGPKey.from_blob(blob)
            self.keys[name] = key

    # Delete all previously loaded keys
    def clear_keys(self):
        self.keys = {}

    # Delete an individual key by name
    def delete_key(self, name):
        if name in self.keys:
            self.keys.pop(name, None)

    # Sign the supplied plain text
    def sign(
            self,
            plain_text,
            signing_key,
            compression=pgpy.constants.CompressionAlgorithm.Uncompressed,
            encoding='ascii'
    ):
        # Retrieve the public key from storage
        signing_key = self.keys[signing_key]

        # The encryption library will generate a warning about the key being used not being able to encrypt/decrypt
        # a message, and that it will try (and succeed) to use a sub-key. To prevent this flooding CloudWatch
        # unnecessarily, we will suppress this specific warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # Create a PGP message containing the unencrypted text
            message_unencrypted = pgpy.PGPMessage.new(
                message=plain_text,
                encoding=encoding,
                compression=compression
            )

            # Sign the message by logically or'ing with signature
            message_signed = message_unencrypted | signing_key.sign(subject=message_unencrypted)

            # If we did receive a warning ensure it is only the one about using the the sub-key
            if -1 in w:
                if issubclass(w[-1].category, UserWarning):
                    assert 'does not have the required usage flag' in str(w[-1].message)
                    assert 'EncryptStorage, EncryptCommunications; using subkey' in str(w[-1].message)

            # Turn warnings back on
            warnings.simplefilter('default')

        # Return the encrypted message
        return message_signed

    # Sign the supplied plain text then encrypt it
    def sign_and_encrypt(
            self,
            plain_text,
            encryption_key,
            signing_key,
            compression=pgpy.constants.CompressionAlgorithm.Uncompressed,
            cipher=pgpy.constants.SymmetricKeyAlgorithm.AES256,
            encoding='ascii'
    ):
        # Retrieve the public key from storage
        encryption_key = self.keys[encryption_key]

        # The encryption library will generate a warning about the key being used not being able to encrypt/decrypt
        # a message, and that it will try (and succeed) to use a sub-key. To prevent this flooding CloudWatch
        # unnecessarily, we will suppress this specific warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            # Create a signed message from the supplied text
            message_signed = self.sign(
                plain_text=plain_text,
                signing_key=signing_key,
                compression=compression,
                encoding=encoding
            )

            # Encrypt the signed message
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
        return message_encrypted

    # Decrypt the supplied cipher text (or encrypted PHP message)
    def decrypt(self, cipher_text, key_name):
        # Retrieve the private key from storage
        private_key = self.keys[key_name]

        # The encryption library will generate a warning about the key being used not being able to encrypt/decrypt
        # a message, and that it will try (and succeed) to use a sub-key. To prevent this flooding CloudWatch
        # unnecessarily, we will suppress this specific warning
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            # Create a PGP message from the cipher text
            pgp_message_encrypted = pgpy.PGPMessage.from_blob(str(cipher_text))

            # Decrypt the message
            pgp_message_unencrypted = private_key.decrypt(pgp_message_encrypted)

            # If we did receive a warning ensure it is only the one about using the the sub-key
            if -1 in w:
                if issubclass(w[-1].category, UserWarning):
                    assert 'Message was encrypted with this key\'s subkey' in str(w[-1].message)
                    assert 'Decrypting with that' in str(w[-1].message)

            # Turn warnings back on
            warnings.simplefilter('default')

        # Return the unencrypted message
        return pgp_message_unencrypted.message
