#!/bin/sh

#  before_tests.sh
#  SSLService
#
#  Created by Bill Abt on 12/12/18.
#

# First delete the old keychain (if present)...
security delete-keychain SSLService.keychain && echo "Old keychain deleted..." || echo "Keychain SSLService.keychain does not exist."

# Create the new keychain with a password...
security create-keychain -p SSLService SSLService.keychain && echo "SSLService.keychain created..." || echo "ERROR: Could not create SSLService.keychain."

# Make the custom keychain the default so that SSLService unit tests will use it...
security default-keychain -s SSLService.keychain || echo "ERROR: Could not make SSLService.keychain the default keychain."

# Unlock the keychain to allow use by unit tests...
security unlock-keychain -p SSLService SSLService.keychain && echo "Keychain unlocked, ready to set timeout..." || echo "ERROR: Keychain could not be unlocked."

# Prevent the keychain from relocking before Travis can run the tests.  An hour ought to do it...
security set-keychain-settings -t 3600 -u SSLService.keychain && echo "Keychain timeout set. Ready for import..." || echo "ERROR: Unable to set keychain lock timeout value."

# Show the status of the unlock...
security show-keychain-info SSLService.keychain

# Import the private keys into the keychain...
security import ./osx/SSLServiceCert.p12 -k SSLService.keychain -t priv -f pkcs12 -P kitura -A && echo "Import complete.  Ready for testing..." || echo "ERROR: Could not import PKCS12 file."

