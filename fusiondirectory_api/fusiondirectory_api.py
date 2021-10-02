"""
A wrapper for the webservice (RPC API) for FusionDirectory.
"""

import requests
import json

class FusionDirectoryAPI:
    def __init__(
        self,
        host,
        user,
        password,
        database,
        verify_cert=True,
        login=True,
        enforce_encryption=True,
        client_id="python_api_wrapper",
        dialog_uri="rest.php/v1/",
    ):
        """
        Log in to FusionDirectory server (Request a session ID)

        Args:
            host: The address of the FusionDirectory host including protocol (https://)
            user: The name of the FD user to log in as
            password: The password of the FD user
            database: The database to use (As seen in FD GUI)
            verify_cert: Verify server certificate (Default: True).
            See requests documentation for options (https://2.python-requests.org/en/master/user/advanced/#verification)
            login: Automatically log in on object instantiation (Default: True)
            enforce_encryption: Raise an exception if traffic is unencrypted (Not https:// in host)
            dialog_uri: could be jsonrpc.php for webservice 1.4 or rest.php/v1/ for version 1.4 of FusionDirectory or RPC before (see https://rest-api.fusiondirectory.info/)
        """

        # Must encrypt traffic
        if "https://" not in host and enforce_encryption:
            raise ValueError("Unencrypted host not allowed: {host}")

        if "rest.php" not in dialog_uri:
            self._use_rest_api = False
        else:
            self._use_rest_api = True

        # The session to use for all requests
        self._session = requests.Session()

        # The URL of the FD server
        self._url = f"{host}/{dialog_uri}"

        # Log in to get this ID from FD
        self._session_id = None

        # Pass to requests
        self._verify_cert = verify_cert

        # Send this ID with all requests
        self._client_id = client_id

        # Login to FD (Get a session_id)
        if login:
           self.login(user, password, database)

    def delete_object(self, object_type, object_dn):
        """
        Delete an object

        Args:
            object_type (str): The type of the object to remove
            object_dn (str): The DN of the object to remove

        Returns:
            True on success
        """
        data = {
            "method": "delete",
            "params": [self._session_id, object_type, object_dn],
        }
        r = self._post(data)
        # Api returns nothing on success, so anything is an error
        if r:
            raise LookupError(r)
        else:
            return True

    def get_base(self):
        """
        Return the configured LDAP base for the selected LDAP
        in this webservice session (see login)
        """
        if self._use_rest_api :
            response = "no equivalence for getBase trough API rest"
        else:
            data = {"method": "getBase", "params": [self._session_id]}
            response = self._post(data)
        return response

    def get_fields(self, object_type, object_dn=None, tab=None):
        """
        Get all fields of an object type as they are stored in FusionDirectory.
        Not very usefull unless using data for a GUI.

        Args:
            object_type (str): The type of object to get the fields for
            dn (str): The optional object to load values from
            tab (str): The name tab to show (main by default)

        Returns:
            All FD attributes organized as sections
        """
        if self._use_rest_api :
            if object_dn :
                response = self._get("objects/"+ object_type+"/"+ object_dn)
            else :
                response = self._get("types/"+ object_type+"/"+tab)
        else :
            data = {
                "method": "getFields",
                "params": [self._session_id, object_type, object_dn, tab],
            }
            response = self._post(data)
        return response

    def get_number_of_objects(self, object_type, ou=None, filter=None):
        """
        Get the number of a given object type limited by OU and/or filter

        Args:
            object_type (str): The object type
            ou (str): The OU to search for objects in. Base is used if OU is None (should be mandatory ?)
            filter (str): An LDAP filter to limit the results

        Returns:
            The number of objects of type object_type in the OU (int)
            Some object types including "DASHBOARD", "SPECIAL", "LDAPMANAGER"
            maybe others, results in a None value from the API. This functions
            returns -1 in those cases.
        """
        if self._use_rest_api :
            payload={}
            if ou :
                payload.update({ 'base' : ou })
            if filter:
                payload.update({ 'filter' : filter })

            response = self._get("objects/"+ object_type, payload)
            r = len(json.loads(response))

        else:
            data = {
                "method": "count",
                "params": [self._session_id, object_type, ou, filter],
            }
            r = self._post(data)

        # The API returns None for some object types
        # I'm aware of these: ["DASHBOARD", "SPECIAL", "LDAPMANAGER"]
        # Let's return -1, so we always return an int
        if r == None:
            r = -1
        # assert type(r) == int
        return r

    def get_session_id(self):
        """
        Get current session ID

        Returns:
            The currents session id (str)
        """
        # Not logged in
        if not self._session_id:
            return self._session_id

        if self._use_rest_api:
            response = self._get("token")
        else:
            data = {"method": "getId", "params": [self._session_id]}
            response = self._post(data)
        return response

    def get_object(self, object_type, dn, attributes={"objectClass": "*"}):
        """
        Get attributes for a single object.

        Arguments:
            object_type (str): The object type to list
            dn: The DN of the object to retrieve
            attributes: The attributes to fetch.
            If this is a single value, the resulting dictionary will have
            for each dn the value of this attribute.
            If this is an array, the keys must be the wanted attributes,
            and the values can be either 1, '*', 'b64' or 'raw'
            depending if you want a single value or an array of values.
            Other values are considered to be 1.
            'raw' means untouched LDAP value and is only useful for dns.
            'b64' means an array of base64 encoded values and is mainly useful for binary attributes.

        Returns:
            A dictionary of attributes for the object
        """
        # Grab the left most part of the dn (uid=??) as filter
        f = dn.split(",")[0]
        filter = f"({f})"
        # DN with out left most part is OU (Base for search)
        ou = ",".join(dn.split(",")[1:])
        data = {
            "method": "ls",
            "params": [self._session_id, object_type, attributes, ou, filter],
        }
        # FIXME: Check what data is returned if no objects are found
        r = self._post(data)
        # API returns an empty list is on no results. I need a dict.
        if r == []:
            r = {}
        else:
            # Api returns the user's data as value for key DN. We just
            # want the value (The LDAP fields)
            r = r[dn]
        # assert type(r) == dict
        return r

    def get_objects(self, object_type, attributes=None, ou=None, filter=None,templates=None,scope="subtree"):
        """
        Get objects of a certain type. Potentially with LDAP attributes and limited
        by OU and/or a filter.

        Arguments:
            object_type (str): The object type to list
            attributes: The attributes to fetch.
            If this is a single value, the resulting dictionary will have
            for each dn the value of this attribute.
            If this is an array, the keys must be the wanted attributes,
            and the values can be either 1, '*', 'b64' or 'raw'
            depending if you want a single value or an array of values.
            Other values are considered to be 1.
            'raw' means untouched LDAP value and is only useful for dns.
            'b64' means an array of base64 encoded values and is mainly useful for binary attributes.
            ou (str): The LDAP branch to search in, base will be used if it is None
            filter (str): An additional filter to use in the LDAP search.

        Returns:
            A list of objects as a dictionary with DN as keys (list)
        """
        if self._use_rest_api :
            payload={}
            if ou :
                payload.update({'base' : ou})
            if filter:
                payload.update({'filter' : filter})
            if attributes :
                attributes_string=""
                for key, value in attributes.items():
                    attributes_string = attributes_string + "attrs["+str(key)+"]="+str(value)+"&"
            if templates:
                payload.update({'templates' : templates})
            if scope:
                payload.update({'scope' : scope})
            r = self._get("objects/"+ object_type+"?"+attributes_string, payload)
        else :
            data = {
                "method": "ls",
                "params": [self._session_id, object_type, attributes, ou, filter],
            }
            # FIXME: Check what data is returned if no objects are found
            r = self._post(data)
            # An empty list is returned on no results. I need a dict.
            if r == []:
                r = {}
        # assert type(r) == dict
        return r

    def get_databases(self):
        """
        List LDAP databases/servers managed by FD. These are the valid
        values for the 'database' argument in login()

        Returns:
            A dict of databases managed by FusionDirectory. Key is id,
            value is displayable name.
        """
        if self._use_rest_api :
            response = self._get("directories")
        else:
            data = {"method": "listLdaps", "params": []}
            response = self._post(data)
        return response

    def get_object_types(self):
        """
        Get object types known to the server

        Returns:
            A dictionary with object type as key and
            object name (Used in GUI) as value
        """
        if self._use_rest_api :
            response = self._get("types")
        else :
            data = {"method": "listTypes", "params": [self._session_id]}
            response = self._post(data)
        return response

    def get_tabs(self, object_type, object_dn=None):
        """
        Get tabs for on an object type. If a DN is supplied
        the data returned will show if the tab is active
        for the object with the supplied DN.

        Args:
            object_type (str): The object type to get tabs for
            object_dn (str): The dn of an object to get active values from

        Returns:
            A dictionary with tabs as keys and a dictionary with
            tab name (str) and active (Bool)
        """
        if self._use_rest_api:
           if object_dn:
               response = self._get("objects/"+object_type+"/"+object_dn)
           else:
               response = self._get("types/"+object_type)
        else:
            data = {
                "method": "listTabs",
                "params": [self._session_id, object_type, object_dn],
            }
            response = self._post(data)
        return response

    def get_object_type_info(self, object_type):
        """
        Get the information on an object type

        Args:
            object_type: The type of object to get information for

        Returns:
            A dictionary of information on the object type
        """
        if self._use_rest_api:
            response = self._get("types/"+object_type)
        else:
            data = {"method": "infos", "params": [self._session_id, object_type]}
            response = self._post(data)
        return response

    def user_is_locked(self, user_dn):
        """
        Is the user locked?

        Args:
            user_dn (str/list): A single DN or a list of DNs

        Returns:
            True if user locked. False if not locked.
        """
        if self._use_rest_api:
            response = self._get("userlock/"+user_dn)
        else:
            # API accepts both list of DNs and a single DN. I don't
            if type(user_dn) != str:
                raise ValueError("user_dn must be a string")
            data = {"method": "isUserLocked", "params": [self._session_id, user_dn]}
            r = self._post(data)
            # API returns a dict with DN as key, and 0 or 1 in value
            # assert len(r) == 1
            # Return value in dict as bool
            response = bool(list(r.values())[0])
        return response

    def lock_user(self, user_dn):
        """
        Lock a user

        Args:
            user_dn (str): The DN of the user to lock

        Returns:
            Bool: True on success
        """
        if self._use_rest_api:
            payload={"foo": True}
            self._put("userlock/" + user_dn, payload)
        else:
            data = {"method": "lockUser", "params": [self._session_id, user_dn, "lock"]}
            self._post(data)
        return True

    def login(self, user, password, database):
        """
        Login to FD by getting a session ID to include in posts

        Args:
            user (str): The username to login as
            password (str): The password of the user
            database (str): The name of the LDAP database/server to use

        Returns:
            Session id (str)
        """

        if self._use_rest_api:
            #self._url = self._url + "/login"
            data = {"directory": database, "user": user,"password" : password}
            self._session_id = self._post(data,"/login")

        else:
            data = {"method": "login", "params": [database, user, password]}
            self._session_id = self._post(data)
        return self._session_id

    def logout(self):
        """
        Log out of FusionDirectory. Deletes session ID

        Returns:
            Bool: True
        """
        data={}
        if self._use_rest_api:
            r=self._post(data,"logout")
        else:
            data = {"method": "logout", "params": [self._session_id]}
            r = self._post(data)
        self._session_id = None
        return r

    def get_recovery_token(self, email):
        """
        Generate a password recovery token for a user

        Args:
            email (str): An email address associated with a user

        Returns:
            A recovery token (str)
        """
        if self._use_rest_api:
            payload = {'email': email}
            r=self._get("recovery",payload)
            response = json.loads(r)['token']
        else:
            data = {"method": "recoveryGenToken", "params": [self._session_id, email]}
            r = self._post(data)
            response = r["token"]
        # FIXME: I get no UID in the dict (Value == None).
        # According to the documentation, I should?
        return response

    def get_template(self, object_type, template_dn):
        """
        Get a template

        Args:
            object_type (str): The type of the object the template is for
            dn (str): The DN of the template

        Returns:
            dict: FusionDirectory attributes organized as tabs
        """
        if self._use_rest_api:
            r=self._get("objects/"+ str(object_type) + "/" + str(template_dn) + "/templatefields")
            response = r
            # FIXME : REST response is smaller than RPC's but correct too
        else:
            data = {
                "method": "gettemplate",
                "params": [self._session_id, object_type, template_dn],
            }
            response = self._post(data)
        return response

    def delete_tab(self, object_type, object_dn, tab):
        """
        Deletes a tab, with fields, from an object

        Args:
            object_type (str): The type of the object to remove a tab from
            object_dn (str): The dn of the object to remove a tab from
            tab (str): The tab to remove

        Returns:
            The object DN on success
        """
        data = {
            "method": "removetab",
            "params": [self._session_id, object_type, object_dn, tab],
        }
        return self._post(data)

    def _set_fields(self, object_type, object_dn, values):
        """
        Update an object

        Args:
            object_type (str): The type of the object to update
            object_dn (str): The dn of the object to update (Creates new object if None)
            values (str): A dictionary of values to update the object with.
            First level keys are tabs, second level keys should be the same
            keys returned by get_fields (without section, directly the attributes).

        Returns:
            The object DN on success
        """
        if self._use_rest_api:
            response = self._patch("objects/"+object_type+"/"+object_dn, payload=values)
        else:
            data = {
                "method": "setFields",
                "params": [self._session_id, object_type, object_dn, values],
            }
            response=self._post(data)
        return response

    def create_object(self, object_type, values, template_dn=None):
        """
        Create a new object. Optionally from a template.

        Args:
            object_type (str): The type of object to create
            values (dict): The values to use for the new object.
            template_dn (str): Optional template for object creation
            Outher keys are tabs, then fields with values

        Returns:
            The DN of the created object (str)
        """
        if template_dn:
            if self._use_rest_api:
                rest_values = {'attrs' : values, "template": template_dn}
                response = self._post(rest_values,"objects/"+object_type)
            else:
                response = self._create_object_from_template(object_type, template_dn, values)
        else:
            if self._use_rest_api:
                rest_values = {'attrs' : values}
                response = self._post(rest_values,"objects/"+object_type)
            else:
                response = self._set_fields(object_type, None, values)
        return response

    def update_object(self, object_type, object_dn, values):
        """
        Update an object

        Args:
            object_type (str): The type of object update
            values (dict): A dictionary of tabs->field:value
            object_dn (str): The DN of the object to update

        Returns:
            The DN of the updated object (str)
        """
        return self._set_fields(object_type, object_dn, values)

    def set_password(self, uid, password, token):
        """
        Set the password of a user

        Args:
            uid (str): UID of the user to change password for
            password (str): The new password for the user
            token (str): a token generated by a get_recovery_token()

        Returns:
            True on success
        """
        data = {
            "method": "recoveryConfirmPasswordChange",
            "params": [self._session_id, uid, password, password, token],
        }
        return self._post(data)

    def unlock_user(self, user_dn):
        """
        Unlock a user

        Args:
            user_dn (str): The DN of the user to unlock

        Returns:
            result: True on success
        """
        if self._use_rest_api:
            # empty payload is mandatory to unlock
            payload={}
            self._put("userlock/" + user_dn, payload)
        else:
            data = {"method": "lockUser", "params": [self._session_id, user_dn, "unlock"]}
            self._post(data)
        return True

    def _create_object_from_template(self, object_type, template_dn, values):
        """
        Create an object from a template

        Args:
            object_type (str): The type of the object to create
            template_dn (str): The dn of the template to use
            values (str): A dictionary of values for the fields in the new object.
            First level keys are tabs, second level keys should be the same
            keys returned by get_fields (without section, directly the attributes).

        Returns:
            The object DN of the new object on success
        """
        data = {
            "method": "usetemplate",
            "params": [self._session_id, object_type, template_dn, values],
        }
        r = self._post(data)
        return r

    def _get(self, uri, payload=None):
        """
        Send data to the FusionDirectory server
        get is only used by REST api

        Args:
            uri build

        Returns:
            result: The value of the key 'result' in the JSON returned by the server
        """

        # Post
        r = self._session.get(self._url + uri, verify=self._verify_cert, headers={'Session-Token':self._session_id}, params=payload)
        # Raise exception on error codes
        r.raise_for_status()
        # Get the json in the response
        #print(r.url)

        return r.text

    def _put(self, uri, payload=None):
        """
        Send data to the FusionDirectory server
        get is only used by REST api

        Args:
            uri build

        Returns:
            result: The value of the key 'result' in the JSON returned by the server
        """

        # Post
        r = self._session.put(self._url + uri, verify=self._verify_cert, headers={'Session-Token':self._session_id}, json=payload)
        # Raise exception on error codes
        r.raise_for_status()
        # Get the json in the response
        #print(r.url)

        return r.text

    def _patch(self, uri, payload=None):
        """
        Send data to the FusionDirectory server
        get is only used by REST api

        Args:
            uri build
            payload

        Returns:
            result: The value of the key 'result' in the JSON returned by the server
        """

        # Post
        r = self._session.patch(self._url + uri, verify=self._verify_cert, headers={'Session-Token':self._session_id}, json=payload)
        # Raise exception on error codes
        #r.raise_for_status()
        # Get the json in the response
        #print(r.url)

        return r.text

    def _post(self, data, uri=""):
        """
        Send data to the FusionDirectory server

        Args:
            data: The data to post

        Returns:
            result: The value of the key 'result' in the JSON returned by the server
        """


        # with REST api , url coudl change, so if url isn't specified we take main url ( mainly for RPC method)
        url=self._url + uri

        if self._use_rest_api:
            headers={'Session-Token':self._session_id}
        else:
        # Client ID (Se we can identify calls in server logs?
            data["id"] = self._client_id
            headers={}
        # Post
        r = self._session.post(url, json=data, verify=self._verify_cert,headers=headers)
        # Raise exception on error codes
        if not self._use_rest_api:
            r.raise_for_status()
        # Get the json in the response
        r = r.json()
        if self._use_rest_api:
            return r
        else:
            if r["error"]:
                raise LookupError(f"FD returned error: {r['error']}")
            else:
                # The result value can have the key errors with a list
                if type(r["result"]) == dict and r["result"].get("errors"):
                    raise LookupError("".join(r["result"]["errors"]))
                else:
                    return r["result"]
