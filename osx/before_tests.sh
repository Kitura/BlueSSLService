#!/bin/sh

#  before_tests.sh
#  SSLService
#
#  Created by Bill Abt on 12/12/18.
#  

# First delete the old keychain (if present)...
security delete-keychain SSLService.keychain && echo "Old keychain deleted..." || echo "Keychain SSLService.keychain does not exist."

# Now copy our test keychain to ~/Library/Keychains folder...
cp osx/SSLService.keychain-db ~/Library/Keychains

# Make the custom keychain the default so that SSLService unit tests will use it...
security default-keychain -s SSLService.keychain || echo "ERROR: Could not make SSLService.keychain the default keychain."

# Unlock the keychain to allow use by unit tests...
security unlock-keychain -p SSLService SSLService.keychain && echo "Keychain unlocked, ready to test..." || echo "ERROR: keychain could not be unlocked."
