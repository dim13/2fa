# 2fa TOTP for CLI

## Usage

Add key:

    2fa -add otpauth://totp/Example:alice@google.com?issuer=Example&secret=JBSWY3DPEHPK3PXP

Evaluate all keys:

    2fa

Evaluate specific keys:

    2fa example

Remove key: edit `~/.2fa`
