# BurpSSOExtension
An extension for BurpSuite that highlights SSO messages in Burp's proxy window.
It is developed by the Chair of Network and Data Security, Ruhr University 
Bochum (http://nds.rub.de/) and the 3curity GmbH (http://3curity.de/).

## Features

- Highlights SSO messages in proxy window, incl. the SSO type.
- Supported Protocols: SAML, OpenID, OAuth, BrowserId
- View and edit SAML messages.
- Detect OpenID login possibilities on websites (other protocols will follow).

## Build
```bash
$ mvn clean package
```
## Installation and Usage

- Build the JAR file as described above, or download it from https://github.com/RUB-NDS/BurpSSOExtension/releases
- Load the JAR file from the target folder into Burp's Extender.
- SSO messages are highlighted automatically in Burp's HTTP history (Proxy tab).
