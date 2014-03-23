# google-password-generator

## Overview

Many large Google Apps customers want to allow non-SAML capable devices to login to Google Apps (iOS, IMAP, etc) however they do not want to sync their corp passwords to Google.  These customer also cannot use a ASPs because they do not have ways to restrict how many ASPs are used by a user or how often are ASPs created.

This Password Generator solution provides a self-service application customers can deploy to their end users to enable users to create a Google Apps password for the use with iOS, IMAP or other clients that require a password to be stored at Google.

This project also contains examples of cross-site scripting (XSS) and cross-site request forgery (XSRF) protections implemented in an App-Engine project.

## Access Controls
The Password Generator tool has built in access controls so administrators can control explicitly which users in the domain can use the Password Generator tool. In the Administration settings of the Password Generator tool the administrator can specify a specific Google Group a user must be a member of in order to use the tool. If the user does not have access to the tool, they are not allowed access to the tool.

## Deployment

Please reviw [setup/deploy.pdf](https://raw.githubusercontent.com/google/googleapps-password-generator/master/deploy.pdf] for detailed setup and app-engine deployment instructions.

## Quick Sheet / Screen Shots

Review [setup/quicksheet.pdf](https://raw.githubusercontent.com/google/googleapps-password-generator/master/setup/quicksheet.pdf) for example screen shots of the project in action.

## Support

For questions and answers join/view the
[googleapps-password-generator Google Group](https://groups.google.com/forum/#!forum/googleapps-password-generator).
