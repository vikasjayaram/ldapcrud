'use strict';
const ldap = require('ldapjs');
const _ = require('underscore');
const utils = require('./utils');

class LDAPCRUD {
  constructor(config) {
    this.config = config;

    // Alias for read
    this.findUsers = this.read;

    this.utils = utils;
  }

  /**
   * Convert LDAP User model to yours format or vice versa.
   * `model` param of config is required. Also you can use `flatten` module, if
   * you have nested user object
   *
   * ### Example:
   *
   * ```javascript
   * let user = flatten({
   *   name: {
   *     first: 'John',
   *     last: 'Doe'
   *   },
   *   email: 'johndoe@mail.com'
   * });
   * let ldapModel = ldap.convertModel(user, true);
   *
   * // ldapModel === {
   * //   sn: 'Doe',
   * //   givenName: 'John',
   * //   mail: 'johndoe@mail.com'
   * // }
   * ```
   *
   * @param {object} data (JS object)
   * @param {boolean} [toLdapModel] (if true convert Node model to LDAP,
   * else LDAP to Node)
   * @return {object} result model
   */
  convertModel(data, toLdapModel) {
    if (!this.config.model) return new Error('No model option in config');
    if (!toLdapModel) toLdapModel = false;
    let result = {};
    let input = _.keys(this.config.model);
    let output = _.values(this.config.model);

    // swap keys
    if (toLdapModel) {
      let temp = input;
      input = output;
      output = temp;
    }

    for (let i = input.length - 1; i >= 0; i--)
      result[output[i]] = data[input[i]];

    return JSON.parse(JSON.stringify(result));
  }


  /**
   * Create LDAP client
   *
   * ### Example:
   *
   * ```javascript
   * ldap.createClient((err, client) => {
   *   // Handle error and do something
   * });
   * ```
   *
   * @param {string} [dn] (custom User DN for bind)
   * @param {string} [password] (custom password for bind)
   * @param {function} callback (callback(err, client))
   */
  createClient(dn, password, callback) {
    let client = ldap.createClient(this.config.clientOptions);

    if (typeof dn === 'function') {
      callback = dn;
      dn = this.config.userDN;
      password = this.config.password;
    }

    client.bind(dn, password, (err) => {
      if (err) {
        client.unbind();
        return callback(err);
      }

      callback(null, client);
    });
  }


  /**
   * LDAP Authentication
   *
   * ### Example:
   *
   * ```javascript
   * let dn = '(sAMAccountName=username)';
   * let pwd = 'secret';
   * ldap.authenticate(dn, pwd, (err, auth) => {
   *   if (err) return console.error(err);
   *   console.log('Authorize:', (auth) ? 'success' : 'failed');
   * });
   * ```
   *
   * @param {string} dn (User DN for bind)
   * @param {string} password (bind password)
   * @param {function} callback (callback(err, auth))
   * @return {*} interrupt executing on error
   */
  authenticate(dn, password, callback) {
    // Skip authentication if an empty username or password is provided.
    if (!dn || !password) {
      let err = {
        code: 0x31,
        errno: 'LDAP_INVALID_CREDENTIALS',
        description: 'The supplied credential is invalid'
      };
      return callback(err);
    }

    this.createClient(dn, password, (err) => {
      let auth = true;

      if (err) {
        if (err.name !== 'InvalidCredentialsError') return callback(err);
        auth = false;
      }

      callback(null, auth);
    });
  }


  /**
   * Create entry in LDAP by provided entry properties.
   *
   * * `displayName`, `cn`, `name` properties generetes from `sn` and
   * `givenName`.
   * * `dn / distinguishedName` generetes by `cn`, provided `dn` property and
   * `baseDN` property of config
   * * `userPrincipalName` concatenates from provided `sAMAccountName` property
   * and `suffix` property of config
   *
   * ### Example:
   *
   * ```javascript
   * let entry = {
   *   sn: 'User',
   *   givenName: 'Test',
   *   sAMAccountName: 'testUser',
   *   mail: 'testUser@mail.com',
   * };
   * ldap.create(entry, (err) => {
   *   // Handle error and do something
   * });
   * ```
   *
   * @param {object} entry (user data)
   * @param {function} callback (callback)
   * @return {*} execute callback with error
   */
  create(entry, callback) {
    if (_.isEmpty(entry)) return callback(new Error('Entry is empty'));

    if (!entry.sn || !entry.givenName)
      return callback(new Error('sn or givenName attributes is empty!'));

    this.createClient((err, client) => {
      if (err) return callback(err);

      if (!entry.displayName)
        entry.displayName = `${entry.givenName} ${entry.sn}`;
      entry.cn = entry.name = entry.displayName;

      let dn = ',';
      if (entry.dn) dn = `,${entry.dn},`;
      dn = `CN=${entry.cn}${dn}${this.config.baseDN}`;

      entry.distinguishedName = dn;
      entry.userPrincipalName = entry.sAMAccountName + this.config.suffix;

      client.add(dn, entry, (err) => {
        if (err) return callback(err);
        callback();
      });
    });
  }


  /**
   * Read entries in LDAP.
   * *`findUsers` is alias for `read`*
   *
   * ### Example:
   *
   * ```javascript
   * ldap.read({
   *   filter: '(sAMAccountName=username)'
   * }, (err, users) => {
   *   // Handle error and do something
   * });
   * ```
   *
   * @param {object} [options] (search options)
   * @param {function} callback (callback)
   */
  read(options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }

    this.createClient((err, client) => {
      if (err) return callback(err);

      if (!options.filter) options.filter = '';
      options.filter = `(&${this.config.defaultFilter + options.filter})`;

      options = _.defaults(
        options, {scope: 'sub', attributes: this.config.attributes}
      );

      client.search(this.config.baseDN, options, (err, res) => {
        if (err) {
          client.unbind();
          return callback(err);
        }

        let response = [];

        res.on('searchEntry', function(entry) {
          let user = _.clone(entry.object);
          delete user.controls;
          response.push(user);
        });

        res.on('searchReference', function(referral) {
          console.log('referral: ' + referral.uris.join());
        });

        res.on('error', (err) => {
          console.error('error: ' + err.message);
        });

        res.on('end', function() {
          client.unbind();
          callback(null, response);
        });
      });
    });
  }


  /**
   * Update user
   *
   * ### Example:
   *
   * Change password in Active Directory
   *
   * ```javascript
   * let pwd = 'secret';
   * let attrs = [
   *   {
   *     type: 'replace',
   *     attr: 'unicodePwd',
   *     value: ldap.utils.encodePassword(pwd)
   *   },
   *   {
   *     type: 'replace',
   *     attr: 'userAccountControl',
   *     value: '66048'
   *   }
   * ];
   *
   * ldap.update('(sAMAccountName=username)', attrs, (err) => {
   *   // Handle error and do something
   * });
   * ```
   *
   * @param {string} filter (LDAP search filter)
   * @param {Array} changedAttrs (array of objects attributes to change)
   * @param {function} callback (callback(err))
   * @return {*} execute callback with error
   */
  update(filter, changedAttrs, callback) {
    if (_.isEmpty(changedAttrs)) return callback(new Error('Changes is empty'));

    let attrs = _.map(changedAttrs, (item) => item.attr);

    // If givenName or sn are changed, rename entry
    let rename = attrs.some((attr) => (['givenName', 'sn'].indexOf(attr) >= 0));

    // if (rename) {
    //   let sn = changedAttrs.find((item) => (item.attr === 'sn'));
    //   let givenName = changedAttrs.find((item) => (item.attr === 'givenName'));
    //   let fullName = `${entry.givenName} ${entry.sn}`;
    //   // entry.cn = entry.name = displayName;

    //   let dn = ',';
    //   if (entry.dn) dn = `,${entry.dn},`;
    //   dn = `CN=${entry.cn}${dn}${this.config.baseDN}`;

    //   entry.distinguishedName = dn;
    // }

    this.read({
      filter: filter,
      attributes: attrs
    }, (err, users) => {
      if (err) return callback(err);

      let user = users[0];

      this.createClient((err, client) => {
        if (err) {
          client.unbind();
          return callback(err);
        }

        let changes = [];
        _.each(changedAttrs, (value) => {
          let mod = {};
          let attr = value.attr;
          mod[attr] = (value.type === 'delete') ? user[attr] : value.value;

          if (!_.isUndefined(mod[attr]))
            changes.push(new ldap.Change({
              operation: value.type,
              modification: mod
            }));
        });

        if (changes.length === 0) return callback();

        client.modify(user.dn, changes, (err) => {
          if (err) return callback(err);
          callback();
        });
      });
    });
  }


  /**
   * Delete user
   *
   * ### Example:
   *
   * ```javascript
   * ldap.delete('(sAMAccountName=username)', (err) => {
   *   // Handle error and do something
   * });
   * ```
   *
   * @param {string} filter (LDAP search filter)
   * @param {function} callback (callback(err))
   * @return {*} execute callback with error
   */
  delete(filter, callback) {
    if (!filter) return callback(new Error('Filter is required'));
    this.read({filter: filter}, (err, users) => {
      if (err) return callback(err);

      this.createClient((err, client) => {
        if (err) return callback(err);

        client.del(users[0].dn, (err) => {
          if (err) return callback(err);
          callback();
        });
      });
    });
  }


  /**
   * Move user to other DN. **Work in progress! Not tested!**
   * @param {string} filter (LDAP search filter)
   * @param {string} newDN (new DN for user without cn)
   * @param {function} callback (callback(err))
   * @return {*} execute callback with error
   */
  move(filter, newDN, callback) {
    if (!filter) return callback(new Error('filter is required'));

    this.read({filter: filter}, (err, users) => {
      if (err) return callback(err);

      let user = users[0];

      if (!newDN) newDN = user.cn;
      else newDN = `cn=${user.cn},${newDN}`;

      this.createClient((err, client) => {
        if (err) return callback(err);

        client.modifyDN(user.dn, newDN, (err) => {
          if (err) return callback(err);
          callback();
        });
      });
    });
  }
}

module.exports = LDAPCRUD;
