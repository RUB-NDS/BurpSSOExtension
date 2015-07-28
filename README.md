# EsPReSSO
## Extension for Processing and Recognition of Single Sign-On Protocols

The extension is based on the BurpSSO Extension, developed by the [Chair of Network and Data Security, Ruhr University 
Bochum](http://nds.rub.de/) and the [3curity GmbH](http://3curity.de/). The extension is part of a bachelor thesis by [Tim Guenther](https://github.com/TimGuenther) at the [Ruhr-University Bochum](http://rub.de/) in cooperation with [Context Information Security Ltd.](http://contextis.com/).

## Features

### Detecting
Supported Protocols:
- [x] SAML
- [ ] OpenID
- [ ] OAuth
- [ ] BrowserId

### Attacking
- [ ] scripting API
- [ ] external libraries

### Beautifier
- [x] View and edit SAML messages.
- [x] Show SAML in a history tab
- [ ] Syntax Highlight

### Basic functions
- [x] Highlight SSO messages in proxy window, incl. the SSO type.
- [x] Detect OpenID login possibilities on websites (other protocols will follow).

## Build
```bash
$ mvn clean package
```
(Please start Burp with Java 1.8)

## Installation and Usage

- Build the JAR file as described above, or download it from https://github.com/RUB-NDS/BurpSSOExtension/releases
- Load the JAR file from the target folder into Burp's Extender.
- SSO messages are highlighted automatically in Burp's HTTP history (Proxy tab).
- A History, Options and Help can be found in a new tab called 'EsPReSSO'

## Overview
![GitHub Logo](/doc/EsPReSSOFull.png)
