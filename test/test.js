'use strict';
const _ = require('underscore');
const async = require('async');
let ldap = require('./lib/ldapcrud');

/**
 * Generate password hash for Active Directory
 * @param {String} password (clear pwd)
 * @return {String} (hashed password)
 */
function encodePassword(password) {
  return new Buffer('"' + password + '"', 'utf16le').toString();
}

let entry = {
  objectClass: ['top', 'person', 'organizationalPerson', 'user'],
  sn: 'User',
  givenName: 'Test',
  instanceType: 4,
  sAMAccountName: '25126',
  mail: '25126@zolotoykod.ru'
};

let pwd = '123123uu';
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

async.waterfall([
  // Create user
  (cb) => {
    ldap.create(entry, (err) => {
      if (err) return cb(err);
      console.log('User 25126 successfully created!');

      ldap.findUsers({
        filter: `(sAMAccountName=${entry.sAMAccountName})`
      }, (err, users) => {
        if (err) return cb(err);
        cb(null, users[0]);
      });
    });
  },

  // Set user password and userAccountControl
  (user, cb) => {
    ldap.update(`(sAMAccountName=${user.sAMAccountName})`, attrs, (err) => {
      if (err) return cb(err);

      ldap.findUsers({
        filter: `(sAMAccountName=${user.sAMAccountName})`
      }, (err, users) => {
        if (err) return cb(err);
        cb(null, users[0]);
      });
    });
  },

  // Authenticate
  (user, cb) => {
    ldap.authenticate(user.dn, pwd, (err, auth) => {
      if (err) return cb(err);
      console.log('Authorize:', (auth) ? 'success' : 'failed');
      cb(null, user);
    });
  },

  // Delete user
  (user, cb) => {
    ldap.delete(`(sAMAccountName=${user.sAMAccountName})`, (err) => {
      if (err) return cb(err);
      console.log('User deleted');
      cb(null);
    });
    /*
    ldap.move(`(sAMAccountName=${user.sAMAccountName})`,
      'OU=Delete,DC=111,DC=local',
      (err) => {
        if (err) return cb(err);
        console.log('User moved');
        cb(null);
      }
    );
    */
  }
], (err, result) => {
  if (err) return console.log(err);
  console.log(result);
});

/*
// CONVERT USER MODEL
const flatten = require('flat');

let userModel = flatten(JSON.parse(JSON.stringify(req.user)));
console.log(userModel);
let ldapModel = ldap.convertModel(userModel, true);
*/
