# googleapps-password-generator

## Overview

Many large Google Apps customers want to allow non-SAML capable devices to login to Google Apps (iOS, IMAP, etc), however they do not want to sync their corp passwords to Google.  These customer also cannot use ASPs (appliction specific passwords) because they do not have ways to restrict how many ASPs are used by a user or how often ASPs are created.

This Password Generator solution provides a self-service application customers can deploy to their end users to enable users to create a Google Apps password for the use with iOS, IMAP or other clients that require a password to be stored at Google.

This project also contains examples of cross-site scripting (XSS) and cross-site request forgery (XSRF) protections implemented in an App Engine project.

## Key Features

End user self-service password tool for creating Google Apps password.

Automatically generate and configure iOS devices

Support for configuring multiple iOS devices for a single user

Google Group based access control

Detailed Reporting

## Deployment

Review [setup/deploy.pdf](https://github.com/google/googleapps-password-generator/blob/master/setup/deploy.pdf) for detailed setup and App Engine deployment instructions.

## Quick Sheet / Screen Shots

Review [setup/quicksheet.pdf](https://github.com/google/googleapps-password-generator/blob/master/setup/quicksheet.pdf) for example screen shots of the project in action.

## Support

For questions and answers join/view the
[googleapps-password-generator Google Group](https://groups.google.com/forum/#!forum/googleapps-password-generator).


