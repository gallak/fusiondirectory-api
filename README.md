# Introduction
_fusiondirectory-api_ is a Python3 wrapper for the RPC API of LDAP manager [FusionDirectory](https://fusiondirectory-user-manual.readthedocs.io/en/latest/).
You need to enable the plugin _webservice_ in FusionDirectory to be able to use the API.

This wrapper supports the RPC based API in versions of FusionDirectory up to 1.3. This API may be deprecated in version 1.4
as a change to a REST based API is planned.

As FusionDirectory manages data in LDAP, the database can also be updated directly in LDAP. However, using the API has the
following advantages:

* Access for the API user is controlled by access control lists created in the FusionDirectory GUI. No need to configure access on the LDAP server.
* Objects can be created from templates maintained in the FusionDirectory GUI.
* LDAP data can be accessed via HTTP/HTTPS on ports 80/443 instead of through the LDAP ports 389/636.
* Users can be locked/unlocked (Prefix encrypted password with _!_) without giving the API user access to the ldap field _userPassword_.

# About REST API protocol ( from @gallak)

It appears in version 1.4 of fusiondirectory with webservice plugins.
This version try to provide REST dialog method with keeping compatifility with RPC API.
But REST API provide more information and error catching method are not the same ..
Keep in your mind the licence ... no warranty, but contribution are welcomed !

Pay attention /!\
Data returned from REST and RPC could be different  ( mainly about syntax, JSONj returned from RPOC isn't JSON strict , but REST responses are)
Error message management should be reworking

# Installation

Install with pip: `pip3 install fusiondirectory-api`

# Overview
A description of key concepts when working with the FusionDirectory API

## Databases
FusionDirectory can handle more than a single database. In the GUI, the database to use can be selcted from a drop down.
When the using the API, the name of the database to use, must be supplied when logging in.

## Objects
FusionDirectory organizes data in _objects_. There are different types of _object_. One type of object is _USER_.
In general, the object type needs to be specified along with the _object_'s [DN](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names)
when manipulating objects with the API.

The object types supported by an installation of FusionDirectory, depends on which plugins are enabled. The list of objects
in an installation can be retrieved by calling _get_object_types()_.

These are the objects in the FusionDirectory installation of the author of this project:
* CONFIGURATION
* OGROUP
* PRINTER
* ROLE
* WORKSTATION
* SAMBADOMAIN
* USER
* TERMINAL
* SERVER
* MOBILEPHONE
* COUNTRY
* ACLASSIGNMENT
* ACLROLE
* COMPONENT
* GROUP
* DCOBJECT
* DEPARTMENT
* DOMAIN
* LOCALITY
* ORGANIZATION
* PHONE

## Tabs
The data for an _object_, is organized in _tabs_. The tabs available for an object type, depends on the activated plugins.
The tabs available for an object type can be retrieved by calling _get_tabs(OBJECT_TYPE)_. By default, tabs are inactive.
The following dictionary shows the avaiable tabs for the object type _USER_ in the author's installation.
The outher keys are the values which should be used when refering to a tab when using the API. The _name_ is the name
for the tab in the webinterface GUI.

```
{
  'user': {'name': 'User', 'active': True},
  'posixAccount': {'name': 'Unix', 'active': False},
  'personalInfo': {'name': 'Personal', 'active': False},
  'mailAccount': {'name': 'Mail', 'active': False},
  'sambaAccount': {'name': 'Samba', 'active': False},
  'userRoles': {'name': 'Groups and roles', 'active': False},
  'sshAccount': {'name': 'SSH', 'active': False},
  'userCertificates': {'name': 'Certificates', 'active': False},
  'reference': {'name': 'References', 'active': True},
  'ldapDump': {'name': 'LDAP', 'active': True}
}
```
## Templates
Objects can be created from templates. The templates can not be created from the API. They need to be created manually in the GUI.
The DN of the template is needed when creating an object from a template.

# Examples
This section contains som examples showing how to use the API.

## Logging in
Log in, and show available object types.
```
# Import the library
from fusiondirectory_api import FusionDirectoryAPI

# Log in to the FusionDirectory server
api = FusionDirectoryAPI(
  host = "https://ldap.example.org",
  user = "user-name",
  password = "secret-password",
  database = "my-ldap",
  )

# Get the object types available
object_types = api.get_object_types()

# Print the object types
print(object_types)

```

## Creating a new user
Let's create a new object of type __USER__.
Its assumed you have created the object _api_ as shown in the example above.
Note, that the password is a list, because the inner workings are based on the GUI, where
the user has to type the password twice (To confirm). The 1st entry in the list should
be the empty string, the 2nd and 3rd entries must be the password to be used. That is
the 2nd and 3rd entry must be identical.

```
# The data for the new user
values = {
  "user": {
    "uid": "bj",
    "sn": "Jacobsen",
    "givenName": "Bent",
    "userPassword": ["", "secretpassword", "secretpassword"],
  }
}

# Create the new user
new_user_dn = api.create_object("USER", values)

# Print the DN of the new user
print(f"Created new user: {new_user_dn}")
```

## Updating a user
Add an email address to the user we created above.

```
# The data to add to the user
values = {
  "mailAccount": {
    "mail": "bj@example.org"
  }
}

# Update the user
updated_user_dn = api.update_object("USER", new_user_dn, values)

# Print to confirm the change
print(f"Updated data for user: {updated_user_dn}")
```

## Deleting a user
Delete the user from the examples above.

```
# Delete the user
result = api.delete_object("USER", new_user_dn)

# Print to confirm (True)
print(f"Deleted user: {result}")
```

## Retrieving user data
Get data from objects using the method _get_objects(object_type, attributes=None, ou=None, filter="")_.
Set _attributes_ to a dictionary with LDAP attributes as keys, and one of the following as value:

* _1_ : Get a single attribute
* _*_ : Get attribute(s) as list
* _raw_ : Untouched LDAP value
* _b64_ : Base64 encoded data. Usefull for binary data

```
# Get the _cn_ and a list of _objectClass_ for all _USER_ objects in the database.
r = api.get_objects("USER", attributes={"cn": "1", "objectClass": "*"})

# Print the result.
print(r)
```

# Class documentation
Technical documentation. For a description of each medthod, look at doc strings in source code.

## Constructor
* FusionDirectoryAPI(host, user, password, database, login=True)

## Methods
* create_object(object_type, values, template_dn=None)
* delete_tab(object_type, object_dn, tab)
* delete_object(object_type, object_dn)
* get_base()
* get_fields(object_type, object_dn=None, tab=None) (USELESS?)
* get_number_of_objects(object_type, ou=None, filter="")
* get_session_id()
* get_objects(object_type, attributes={"objectType" = "*"}, ou=None, filter=None)
* get_object(object_type, dn, attributes={"objectType" = "*"})
* get_object_type_info(object_type)
* get_object_types()
* get_databases()
* get_tabs(object_type, object_dn=None)
* get_recovery_token(email) (Returns None for UID?)
* get_template(object_type, template_dn) (USELESS?)
* user_is_locked(user_dn)
* lock_user(user_dn)
* unlock_user(user_dn)
* login(user, password, database, verify_cert=True, login=True, enforce_encryption=True, client_id="python_api_wrapper")
* logout()
* set_password(uid, password, token) (TOKEN ALWAYS INVALID?)
* update_object(object_type, object_dn, values)

# Testing
Run tests from project root. You need a running instance of FusionDirectory.
Set up environment variables (Assuming Linux).

* export FD_USER = "user-name"
* export FD_PASSWORD = "secret-password"
* export FD_HOST = "https://fd.example.org"
* export FD_DATABASE = "my-ldap-database"

```
py.test tests.py
```

# Known issues
Know issues go here.
## Tokens returned by get_recovery_token() do not work.
API does not return value for _uid_. When using the token, _FD_ says _"Invalid token"_.

## Useless methods
Some methods, like _get_template()_ & _get_fields(_) do not seem to be usefull.
Consider removal of such methods to cut down on complexity.
