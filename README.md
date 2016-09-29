# PasswordVault
A PowerShell module for using the OS credential manager to securely store and retrieve secrets

Currently supports Windows; however, could presumably be extended to support OSX / *nix keychain commands

In Windows, prior to Win8 we only had cmdkey. In the interests of looking forward, I have assumed the default case is availability of the newer .NET methods, and wrapped the legacy utility to mirror the newer method signatures.

On load, the module determines what OS it is running on and saves a script variable. To extend to *nix, this check would need to be expanded, and functions to wrap the keychain utility would need to be fleshed out.


#Usage:
It's in the comment-based help!
