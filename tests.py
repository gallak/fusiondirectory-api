#!/usr/bin/env python3
import uuid, string, random, os

from fusiondirectory_api import FusionDirectoryAPI

ADMIN_USER_UID = os.getenv("FD_USER")

# Instantiate API object
api = FusionDirectoryAPI(
  host = os.getenv("FD_HOST"),
  user = ADMIN_USER_UID,
  password = os.getenv("FD_PASSWORD"),
  #password = "toto",
  database = os.getenv("FD_DATABASE"),
  enforce_encryption=False,
  dialog_uri="rest.php/v1/",
  #dialog_uri="jsonrpc.php"
  )

# Get the base so we can check DNs (DN must include base)
# OK print(api.get_base())
# OK print(api.get_databases())
# KO print(api.logout())

# OK
# for ot in ["USER"]:
#         print(str(api.get_tabs(ot,"uid=sadgorilla782,ou=people,dc=demo,dc=fusion")))

# OK print(api.get_object_types())
# OK print(api.get_fields('user','',''))
# OK print(api.get_number_of_objects('USER','dc=demo,dc=fusion','(uid=c*)'))
print(api.get_number_of_objects('USER','dc=demo,dc=fusion','(uid=c*)'))

#print(LDAP_BASE)

def random_string(length=32):
    s = ""
    for i in range(32):
        s += random.choice(string.ascii_letters)
    return s

def test_get_session_id():
    session_id = api.get_session_id()
    assert type(session_id) == str
    assert len(session_id) >= 20
    assert session_id == api._session_id

def test_get_base():
    base_dn = api.get_base()
    assert type(base_dn) == str
    assert len(base_dn.split(",")) >= 2

def test_get_fields():
    fields = api.get_fields("USER")
    assert type(fields) == dict

def test_get_fields():
    number_of_users = api.get_number_of_objects("USER")
    assert type(number_of_users) == int
    assert number_of_users > 0

def test_get_objects():
    users = api.get_objects("USER", attributes={"uid": 1, "cn": 1, "objectClass": "*"})
    assert type(users) == dict
    assert len(users.keys()) > 1
    for dn, attributes in users.items():
        assert LDAP_BASE in dn
        assert type(attributes) == dict
        assert len(attributes.keys()) == 3
        assert type(attributes['uid']) == str
        assert type(attributes['cn']) == str
        assert type(attributes['objectClass']) == list
        assert len(attributes['objectClass']) >= 3
        # Let's find only this isuser with a filter
        single_user = api.get_objects("USER", attributes={"uid": 1}, filter=f"(uid={attributes['uid']})")
        assert len(single_user) == 1
        assert list(single_user.values())[0]["uid"] == attributes['uid']

def test_get_databases():
    databases = api.get_databases()
    assert type(databases) == dict
    assert len(databases) >= 1

def test_get_object_types():
    object_types = api.get_object_types()
    assert type(object_types) == dict
    assert len(object_types) >= 1
    for ot in ["USER", "DASHBOARD","COUNTRY","GROUP","ORGANIZATION"]:
        assert ot in object_types.keys()

def test_get_tabs():
    # Asking for tabs on some types will make FD throw an error
    # for ot in api.get_object_types().keys():
    for ot in ["USER", "DASHBOARD","COUNTRY","GROUP","ORGANIZATION"]:
        tabs = api.get_tabs(ot)
        assert type(tabs) == dict
        assert len(tabs) > 1

def test_get_object_type_info():
    for ot in api.get_object_types().keys():
        info = api.get_object_type_info(ot)
        assert type(info) == dict
        assert len(info) > 1

def test_locking():
    users = api.get_objects("USER", attributes={"uid": 1})
    for dn, attributes in users.items():
        original_lock_state = api.user_is_locked(dn)
        assert type(original_lock_state) == bool
        assert LDAP_BASE in dn
        # Don't risk locking admin out
        if attributes["uid"] != ADMIN_USER_UID:
            # Change lock state
            if original_lock_state:
                assert api.unlock_user(dn) == True
            else:
                assert api.lock_user(dn) == True
            # Lock state should be inverted
            assert not(api.user_is_locked(dn)) == original_lock_state
            # Change back to original lock state
            if original_lock_state:
                assert api.lock_user(dn) == True
            else:
                assert api.unlock_user(dn) == True
            # Lock state should be same as original state
            assert api.user_is_locked(dn)  == original_lock_state

def test_get_recovery_token():
    users = api.get_objects("USER", attributes={"mail": 1}, filter="(mail=*)")
    for dn, attributes in users.items():
        assert LDAP_BASE in dn
        token = api.get_recovery_token(attributes["mail"])
        assert type(token) == str
        assert len(token) == 57

# Templates can not be created via API. This test would depend on data in server
def test_get_template():
    pass

# Templates can not be created via API. This test would depend on data in server
def test_create_object_from_template():
    pass

def test_number_of_objects():
    # This is also (better) tested in test_create_objects()
    for ot in api.get_object_types().keys():
        n = api.get_number_of_objects(ot)
        assert type(n) == int

def test_create_objects():
    # FIXME: Different kind of objects
    no_of_users = api.get_number_of_objects("USER")
    assert type(no_of_users) == int
    assert no_of_users >= 1 # We know admin exists
    n = 10
    demo_user_dns = []
    for i in range(n):
        p = random_string(32)
        uid = random_string(32).lower()
        values = {
            "user": {
                "uid": uid,
                "sn": "user",
                "givenName": "demo",
                "userPassword": ["", p, p],
            }
        }
        # Create demo user, add dn to list
        dn = api.create_object("USER", values)
        assert type(dn) == str
        # DN looks like a DN
        assert LDAP_BASE in dn
        # Get the data for the new user from FD
        attrs = {"uid": 1, "sn": 1, "givenName": 1 }
        user_data = api.get_object("USER", dn, attributes=attrs)
        # Check the data we got back
        for a in attrs.keys():
            assert user_data[a] == values["user"][a]
        # Add tab to user
        new_tab_data = {
            "mailAccount": {
                "mail": f"{uid}@example.org"
              }
        }
        updated_user_dn = api.update_object("USER", dn, new_tab_data)
        assert updated_user_dn == dn
        update_attrs = {"mail": 1 }
        # Get updated user
        updated_user_data = api.get_object("USER", dn, attributes=update_attrs)
        # Check the data we got back
        for a in update_attrs.keys():
            assert updated_user_data[a] == new_tab_data["mailAccount"][a]
        # Delete the mail tab
        updated_user_dn = api.delete_tab("USER", dn, "mailAccount")
        assert updated_user_dn == dn
        # Get updated user (With no mail attribute)
        updated_user_data = api.get_object("USER", dn, attributes=update_attrs)
        # Empty dir, because we deleted the mailAccount tab
        assert updated_user_data == {}
        # Save new users dn (So we can delete her)
        demo_user_dns.append(dn)
    # The number of users has increased as expected
    assert api.get_number_of_objects("USER") == (no_of_users + n)
    # Delete demo users
    for dn in demo_user_dns:
        assert api.delete_object("USER", dn) == True
    # Same number of users as before
    assert api.get_number_of_objects("USER") == no_of_users

def test_number_of_objects():
    r = api.logout()
    assert api._session_id == None
    assert api.get_session_id() == None

# set_password()
# LOGIN
# LOGOUT
