# LDAPCRUD

A lightweight wrapper for `ldapjs` for CRUD actions and some more.

Install it via [npm](https://www.npmjs.com/package/ldapcrud)

```
npm install ldapcrud
```

## Setup

First of all, install and require `ldapcrud` module in your script and create new instance of `LDAPCRUD` class with your config;

```javascript
const LDAPCRUD = require('ldapcrud');

let config = {
  clientOptions: {
    url: 'ldaps://your-ldap-url',
    tlsOptions: {
      rejectUnauthorized: false
    }
  },
  baseDN: 'OU=Customers,DC=Company,DC=local',
  userDN: 'CN=serviceadmin,OU=Customers,DC=Company,DC=local',
  password: 'secret',
  attributes: [
    'sAMAccountName',
    'mail',
    'sn',
    'givenName'
  ],
  skipUPN: false,
  defaultFilter: '(mail=*@*)',
  suffix: '@Company.local',
  model: {
    'sAMAccountName': 'ldap',
    'mail': 'email',
    'sn': 'name.last',
    'givenName': 'name.first'
  }
};

let ldap = new LDAPCRUD(config);
```

## Config

* `clientOptions` **object** - options for ldapjs client creation. [See more](http://ldapjs.org/client.html#create-a-client)
* `baseDN` **string** - DN where search users.
* `userDN` **string** - Admin User DN, that can performs operations against the LDAP server.
* `password` **string** - Admin User password.
* `attributes` **Array** - Array of properties to select
* `defaultFilter` **string** - LDAP Filter string
* `suffix` **string** - User model suffix
* `model` **object** - relation LDAP properties to your custom User model, where keys are LDAP properties and values are yours User model fields.

## convertModel(data, [toLdapModel])

Convert LDAP User model to yours format or vice versa.
`model` param of config is required. Also you can use `flatten` module, if
you have nested user object

### Example:

```javascript
let user = flatten({
  name: {
    first: 'John',
    last: 'Doe'
  },
  email: 'johndoe@mail.com'
});
let ldapModel = ldap.convertModel(user, true);

// ldapModel === {
//   sn: 'Doe',
//   givenName: 'John',
//   mail: 'johndoe@mail.com'
// }
```

### Params:

* **object** *data* (JS object)
* **boolean** *[toLdapModel]* (if true convert Node model to LDAP, else LDAP to Node)

### Return:

* **object** result model

## createClient([dn], [password], callback)

Create LDAP client

### Example:

```javascript
ldap.createClient((err, client) => {
  // Handle error and do something
});
```

### Params:

* **string** *[dn]* (custom User DN for bind)
* **string** *[password]* (custom password for bind)
* **function** *callback* (callback(err, client))

## authenticate(dn, password, callback)

LDAP Authentication

### Example:

```javascript
let dn = '(sAMAccountName=username)';
let pwd = 'secret';
ldap.authenticate(dn, pwd, (err, auth) => {
  if (err) return console.error(err);
  console.log('Authorize:', (auth) ? 'success' : 'failed');
});
```

### Params:

* **string** *dn* (User DN for bind)
* **string** *password* (bind password)
* **function** *callback* (callback(err, auth))

### Return:

* interrupt executing on error

## create(entry, callback)

Create entry in LDAP by provided entry properties.

* `displayName`, `cn`, `name` properties generetes from `sn` and
`givenName`.
* `dn / distinguishedName` generetes by `cn`, provided `dn` property and
`baseDN` property of config
* `userPrincipalName` concatenates from provided `sAMAccountName` property
and `suffix` property of config

### Example:

```javascript
let entry = {
  sn: 'User',
  givenName: 'Test',
  sAMAccountName: 'testUser',
  mail: 'testUser@mail.com',
};
ldap.create(entry, (err) => {
  // Handle error and do something
});
```

### Params:

* **object** *entry* (user data)
* **function** *callback* (callback)

### Return:

* execute callback with error

## read([options], callback)

Read entries in LDAP.
*`findUsers` is alias for `read`*

### Example:

```javascript
ldap.read({
  filter: '(sAMAccountName=username)'
}, (err, users) => {
  // Handle error and do something
});
```

### Params:

* **object** *[options]* (search options)
* **function** *callback* (callback)

## update(filter, changedAttrs, callback)

Update user

### Example:

Change password in Active Directory

```javascript
function encodePassword(password) {
  return new Buffer('"' + password + '"', 'utf16le').toString();
}

let pwd = 'secret';
let attrs = [
  {
    type: 'replace',
    attr: 'unicodePwd',
    value: encodePassword(pwd)
  },
  {
    type: 'replace',
    attr: 'userAccountControl',
    value: '66048'
  }
];

ldap.update('(sAMAccountName=username)', attrs, (err) => {
  // Handle error and do something
});
```

### Params:

* **string** *filter* (LDAP search filter)
* **Array** *changedAttrs* (array of objects attributes to change)
* **function** *callback* (callback(err))

### Return:

* execute callback with error

## delete(filter, callback)

Delete user

### Example:

```javascript
ldap.delete('(sAMAccountName=username)', (err) => {
  // Handle error and do something
});
```

### Params:

* **string** *filter* (LDAP search filter)
* **function** *callback* (callback(err))

### Return:

* execute callback with error

## move(filter, newDN, callback)

Move user to other DN. **Work in progress! Not tested!**

### Params:

* **string** *filter* (LDAP search filter)
* **string** *newDN* (new DN for user without cn)
* **function** *callback* (callback(err))

### Return:

* execute callback with error

<!-- End index.js -->
