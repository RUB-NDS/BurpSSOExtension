# EsPReSSO
[![Build Status](https://travis-ci.org/RUB-NDS/BurpSSOExtension.svg?branch=master)](https://travis-ci.org/RUB-NDS/BurpSSOExtension)
![licence](https://img.shields.io/badge/License-GPLv2-brightgreen.svg)
[![release](https://img.shields.io/badge/Release-v3.0-blue.svg)](https://github.com/RUB-NDS/BurpSSOExtension/releases)
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
- [x] DTD- and WS-Attacker integration while interception SAML messages

### Beautifier
- [x] Syntax Highlight
- [x] Highlight SSO messages in proxy window, incl. the SSO type
- [x] Show all recognized SSO messages in a history tab
- [x] Context menu for 'Analyze SSO Protocol'

### Editors/Viewers
- [x] View and edit SAML
- [x] View JSON and JSON Web Token (JWT)

## Build
```bash
$ mvn clean package
```
(Please start Burp with Java 1.8)

## Installation and Usage

- Build the JAR file as described above, or download it from [releases](https://github.com/RUB-NDS/BurpSSOExtension/releases).
- Load the JAR file from the target folder into Burp's Extender. (Start Burp with Java 1.8)
- SSO messages are highlighted automatically in Burp's HTTP history (Proxy tab).
- SAML, JSON and JWT editors and viewers attached automatically.
- A SOO History, Options and Help can be found in a new tab called 'EsPReSSO'.

## Dependencies and Licences

 Dependencie     | Licence                         | Access Date | Link                                                              | Copyright (c) Date, Name                                             |
|-----------------|---------------------------------|-------------|-------------------------------------------------------------------|----------------------------------------------------------------------|
| RSyntaxTextArea | modified BSD license            | 20.09.2015  | https://github.com/bobbylight/RSyntaxTextArea                     | 2012, Robert Futrell                                                 |
| json-simple     | Apache License 2.0              | 20.09.2015  | https://code.google.com/p/json-simple/                            | Unkown, Yidong Fang                                                  |
| WSAttacker      | GNU General Public License v2.0 | 20.09.2015  | https://github.com/RUB-NDS/WS-Attacker/                           | 2012, Christain Mainka, Andreas Falkenberg, Jurai Somorovski, et al. |
| junit           | Eclipse Public License 1.0      | 12.03.2018  | https://github.com/junit-team/junit4                              | Unkown, Erich Gamma and Kent Beck.                                                  |
| jutf7           | MIT license                     | 12.03.2018  | https://sourceforge.net/projects/jutf7/                           | 2011, Jaap Beetstra                                                  |
| commons-io      | Apache License 2.0              | 12.03.2018  | https://github.com/apache/commons-io                              | 2012, Scott Sanders, et al.                                          |

## Tested with:
- Java 1.8.0._151
- Burp Suite 1.7.32
- Ubuntu 16.04.3 LTS, amd64
- Netbeans 8.2
- Maven 3.3.9
