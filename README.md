# aws-credential-manager
Credential manager and tools for switching between multiple sets of AWS ephemeral credentials (as from SAML)

## Rationale
I have to juggle between aws credentials corresponding to multiple accounts (experimentation, shared dev, prod, whatever QA we will have in the future.), and sometimes multiple privilege levels

My employer uses SAML, but not AWS IAM Identity center. Instead, anyone who needs CLI credentials will use a browser extension to get credentials when they sign in to the console with SAML. This means that the $AWS_SHARED_CREDENTIALS_FILE corresponds to whatever account and role was last signed into on the console.

I'd like to have a credential manager that will give me creds for a specific account and role if they are available, and fail if they are not.

## Description
An interface for storing and fetching AWS credentials, keyed either by access key, arn, or account & role_name.
Its also possible to automatically acquire credentials with sts:AssumeRole if the parent user/role credentials are valid. Only a single chain of roles is searched.

## Modules
- multicred/credentials
API for manipulating credentials. Most external interface objects are defined here. Allows constructing new credential objects and initializing boto with credentials
- multicred/interfaces
Abstract APIs for storage and credential resolution modules
- multicred/dbschema
SQLAlchemy table objects used by dbstorage
- multicred/dbstorage
Implementation of the storage interface using SQLalchemy (and typically sqlite)
- multicred/resolver
Implementation of the credential resolutin interface
## Executable scripts
- `multicred-import`
The importer will inspect a file containing credentials (access key id, secret key, and session token), determine the credentials identity with STS, and import the credentials into the database if not already present.
- `multicred-credhelper`  
The credential helper will use command line switches or environment variables to select a target identity, search for that identity, and emit the credentials if they are available.
- `multicred-manage`  
A utility script for examining and manipulating the storage

## Plan

The credentials will be stored in an sqlite database, indexed by account id and role name. The import time will also be stored so the scripts can guess if the credentials are still valid.

## Other branches

There will be code in an _experiments_ branch that's not really practical. It's for learning pytest features and messing with datastructures.

## Future enhancements
The database (or perhaps only the secret key and session token) should be encrypted if the platform allows it.
Unfortunately, my common use case is WSL2, which doesn't allow for convenient use of DPAPI or gnome-keyring