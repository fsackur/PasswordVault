# PasswordVault
A PowerShell module for using the OS credential manager to securely store and retrieve secrets

Currently supports Windows; however, could presumably be extended to support OSX / *nix keychain commands

In Windows, prior to Win8 we only had cmdkey. In the interests of looking forward, I have assumed the default case is availability of the newer .NET methods, and wrapped the legacy utility to mirror the newer method signatures.

On load, the module determines what OS it is running on and saves a script variable. To extend to OSX or Linux, this check would need to be expanded, and functions to wrap the keychain utility would need to be fleshed out.


#Usage
It's in the comment-based help!

However, in general, please note that secrets need to be stored with a Username and Resource field and a Password field. All are strings. The Password field is the only one that is encrypted; assume the other two fields are readable to anyone.

There is scope for hacking extra information into this. For example, for a given resource, you could append information with a character delimiter.
Examples:
```
#Incorporate expiry date for time-limited credential
$ExpiryDate = (Get-Date).AddHours(8)
$ExpiryString = Get-Date $ExpiryDate -Format s
Add-PasswordVaultEntry -Username "MyUsername@domain" -Password "hunter2" -Resource "AppAPIKey#$ExpiryString"
```

```
#Hash an extra proprty into the Resource field to allow storing multiple secrets of the same category
$CustomerAccount = "Omnicorp"
Add-PasswordVaultEntry -Username "MyUsername@domain" -Password "hunter2" -Resource "AppAPIKey#$CustomerAccount"
Get-PasswordVaultEntry | ?{$_.Resource -like "AppAPIKey#$CustomerAccount"} | Get-PasswordVaultEntry
```


#Credit
@toburger for the P/Invoke code in the Get-CMStoredCredential function. Found via @cdhunt
Github and gist links are included in the comment-based help for that function. Apologies for not properly forking; I'm still finding my way with git.


#License
The MIT License

Get-CMStoredCredential function: Copyright (c) 2012 Tobias Burger

Other functions: Copyright (c) 2015 Freddie Sackur, Rackspace


Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
