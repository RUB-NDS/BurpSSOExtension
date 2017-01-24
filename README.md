# EsPReSSO
[![Build Status](https://travis-ci.org/RUB-NDS/BurpSSOExtension.svg?branch=master)](https://travis-ci.org/RUB-NDS/BurpSSOExtension)
![licence](https://img.shields.io/badge/License-GPLv2-brightgreen.svg)
[![release](https://img.shields.io/badge/Release-v2.0.2-blue.svg)](https://github.com/RUB-NDS/BurpSSOExtension/releases)
![status](https://img.shields.io/badge/Status-beta-yellow.svg)

## Extension for Processing and Recognition of Single Sign-On Protocols

The extension is based on the BurpSSO Extension, developed by the [Chair of Network and Data Security, Ruhr University 
Bochum](http://nds.rub.de/) and the [Hackmanit GmbH](http://hackmanit.de/). The extension is part of a bachelor thesis by [Tim Guenther](https://github.com/TimGuenther) at the [Ruhr-University Bochum](http://rub.de/) in cooperation with [Context Information Security Ltd.](http://contextis.com/).


## Features

### Detecting
Supported Protocols:
- [x] SAML
- [x] OpenID
- [x] OAuth
- [x] BrowserId
- [x] OpenID Connect
- [x] Facebook Connect
- [x] Microsoft Account

### Attacking
- [x] WS-Attacker integration while interception SAML messages

### Beautifier
- [x] View and edit SAML messages.
- [x] Show SAML in a history tab
- [x] Syntax Highlight
- [x] Context menu for 'Analyze SSO Protocol'

### Editors
- [x] SAML
- [x] JSON
- [x] JSON Web Token (JWT)

### Basic functions
- [x] Highlight SSO messages in proxy window, incl. the SSO type.
- [x] Detect OpenID login possibilities on websites (other protocols will follow).

## Build
```bash
$ mvn clean package
```
(Please start Burp with Java 1.8)

## Installation and Usage

- Build the JAR file as described above, or download it from [releases](https://github.com/RUB-NDS/BurpSSOExtension/releases).
- Load the JAR file from the target folder into Burp's Extender. (Start Burp with Java 1.8)
- SSO messages are highlighted automatically in Burp's HTTP history (Proxy tab).
- A History, Options and Help can be found in a new tab called 'EsPReSSO'

## Dependencies and Licences

 Dependencie     | Licence                         | Access Date | Link                                          | Copyright (c) Date, Name                                             |
|-----------------|---------------------------------|-------------|-----------------------------------------------|----------------------------------------------------------------------|
| RSyntaxTextArea | modified BSD license            | 20.09.2015  | https://github.com/bobbylight/RSyntaxTextArea | 2012, Robert Futrell                                                 |
| json-simple     | Apache License 2.0              | 20.09.2015  | https://code.google.com/p/json-simple/        | Unkown, Yidong Fang                                                  |
| WSAttacker      | GNU General Public License v2.0 | 20.09.2015  | https://github.com/RUB-NDS/WS-Attacker/       | 2012, Christain Mainka, Andreas Falkenberg, Jurai Somorovski, et al. |

## Tested with:
- Java 1.8.0._60
- Burp Suite 1.6.01
- Arch Linux 4.1.6-1-arch, amd64
- Netbeans 8.0.2
- Maven 3.3.3


