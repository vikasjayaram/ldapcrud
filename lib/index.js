const ldap = require('ldapjs');

/**
 * LDAPCRUD Class
 */
class LDAPCRUD {
  /**
   * LDAPCRUD constructor
   * @param {object} config
   */
  constructor(config) {
    this.config = config;
    this.utils = require('./utils');
  }

  /**
   * Init LDAPCRUD
   * @return {Promise<LDAPCRUD>}
   */
  init() {
    return this.createClient()
      .then((client) => this.client = client)
      .then(() => this);
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
   * @param {object} data to convert
   * @param {boolean} [toLdapModel] if true convert Node model to LDAP,
   * else LDAP to Node
   * @return {object} converted data
   */
  convertModel(data, toLdapModel = false) {
    if (!this.config.model)
      return new ReferenceError('"model" path required');

    let input = Object.keys(this.config.model);
    let output = Object.values(this.config.model);

    // swap keys
    if (toLdapModel)
      [input, output] = [output, input];

    return input.reduce((a, c, i) => {
      a[output[i]] = data[c];
      return a;
    }, {});
  }


  /**
   * Create LDAP client
   *
   * ### Example:
   *
   * ```javascript
   * ldap.createClient()
   *   .then((client) => ...);
   * ```
   *
   * @param {string} [dn] custom User DN for bind
   * @param {string} [password] custom password for bind
   * @return {Promise<Client>} Promise resolved with ldap client
   */
  createClient(dn, password) {
    return new Promise((reject, resolve) => {
      let client = ldap.createClient(this.config.clientOptions);

      dn = this.config.userDN;
      password = this.config.password;

      client.bind(dn, password, (err) => {
        if (err) {
          client.unbind();
          return reject(err);
        }

        resolve(client);
      });
    });
  }


  /**
   * LDAP User Authentication
   *
   * ### Example:
   *
   * ```javascript
   * ldap.authenticate('(sAMAccountName=username)', 'password')
   *   .then((auth) => console.log('Auth:', (auth) ? 'success' : 'failed'));
   * ```
   *
   * @param {string} dn (User DN for bind)
   * @param {string} password (bind password)
   * @return {Promise<boolean>}
   */
  authenticate(dn, password) {
    return new Promise((resolve, reject) => {
      // Skip authentication if an empty username or password is provided.
      if (!dn || !password)
        return reject({
          code: 0x31,
          errno: 'LDAP_INVALID_CREDENTIALS',
          description: 'The supplied credential is invalid'
        });

      return this.createClient(dn, password)
        .then(() => true)
        .catch((err) => {
          if (err.name === 'InvalidCredentialsError') return false;
          throw err;
        });
    });
  }


  /**
   * Create entry in LDAP by provided entry properties.
   *
   * * `displayName`, `cn`, `name` properties generated from `sn` and
   * `givenName`.
   * * `dn / distinguishedName` generated from `cn`, provided `dn` property and
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
   * ldap.create(entry)
   *   .then((data) => ...)
   *   .catch(errorHandler);
   * ```
   *
   * @param {object} entry (user data)
   * @return {Promise}
   */
  create(entry) {
    return new Promise((resolve, reject) => {
      if (!entry.sn || !entry.givenName)
        return reject(
          new ReferenceError('sn and givenName attributes required')
        );

      if (!entry.displayName)
        entry.displayName = `${entry.givenName} ${entry.sn}`;
      entry.cn = entry.name = entry.displayName;

      let dn = ',';
      if (entry.dn) dn = `,${entry.dn},`;
      dn = `CN=${entry.cn}${dn}${this.config.baseDN}`;

      entry.distinguishedName = dn;
      entry.userPrincipalName = entry.sAMAccountName + this.config.suffix;

      this.client.add(dn, entry, (err) => {
        if (err) return reject(err);
        resolve(entry);
      });
    });
  }


  /**
   * Read entries in LDAP
   *
   * ### Example:
   *
   * ```javascript
   * ldap.read({filter: '(sAMAccountName=username)})
   *   .then((users) => ...);
   * ```
   *
   * @param {object} [options] (search options)
   * @return {Promise<Array>}
   */
  read(options = {}) {
    return new Promise((resolve, reject) => {
      if (!options.filter) options.filter = '';
      options.filter = `(&${this.config.defaultFilter + options.filter})`;

      options = Object.assign({
        scope: 'sub',
        attributes: this.config.attributes
      }, options);

      this.client.search(this.config.baseDN, options, (err, res) => {
        if (err) return reject(err);

        let result = [];

        res
          .on('searchEntry', (entry) => {
            let user = Object.assign({}, entry.object);
            delete user.controls;
            result.push(user);
          })
          .on('end', () => resolve(result))
          .on('error', reject);
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
   * ldap.update('(sAMAccountName=username)', attrs)
   *   .then(() => console.log('User successfully updated'));
   * ```
   *
   * @param {string} filter (LDAP search filter)
   * @param {Array} changedAttrs (array of objects attributes to change)
   * @return {Promise}
   */
  update(filter, changedAttrs) {
    let attributes = changedAttrs.map((item) => item.attr);

    // If givenName or sn are changed, rename entry
    let rename = attributes.some((a) => (['givenName', 'sn'].includes(a)));
    let newDN = false;
    if (rename) attributes.push('givenName', 'sn');

    return this.read({filter, attributes}).then((users) => {
      let user = users[0];

      // Get full name
      if (rename) {
        let sn = changedAttrs.find((a) => (a.attr === 'sn'));
        let givenName = changedAttrs.find((a) => (a.attr === 'givenName'));

        sn = (sn ? sn.value : user.sn);
        givenName = (givenName ? givenName.value : user.givenName);
        let fullName = `${givenName} ${sn}`;

        // change displayName
        changedAttrs.push({
          type: 'replace',
          attr: 'displayName',
          value: fullName
        });

        newDN = `CN=${fullName},${this.config.baseDN}`;
      }

      return new Promise((resolve, reject) => {
        let changes = [];
        changedAttrs.forEach((value) => {
          let mod = {};
          let attr = value.attr;
          mod[attr] = (value.type === 'delete') ? user[attr] : value.value;

          if (!this.utils.isUndefined(mod[attr]))
            changes.push(new ldap.Change({
              operation: value.type,
              modification: mod
            }));
        });

        if (changes.length === 0) return resolve(true);

        this.client.modify(user.dn, changes, (err) => {
          if (err) return reject(err);
          if (!rename) return resolve(true);

          this.client.modifyDN(user.dn, newDN, (err) => {
            if (err) return reject(err);
            resolve(true);
          });
        });
      });
    });
  }


  /**
   * Delete users specified by filter
   *
   * ### Example:
   *
   * ```javascript
   * ldap.delete('(sAMAccountName=username)')
   *   .then(() => console.log('User successfully deleted'));
   * ```
   *
   * @param {string} filter (LDAP search filter)
   * @return {Promise}
   */
  delete(filter) {
    return this.read({filter}).then((users) => {
      let deletePromise = (dn) => new Promise((resolve, reject) => {
        this.client.del(dn, (err) => {
          if (err) return reject(err);
          resolve(true);
        });
      });

      return Promise.all(users.map((u) => deletePromise(u.dn)));
    });
  }


  /**
   * Move users to other DN.
   * @param {string} filter LDAP search filter
   * @param {string} newDN new DN for user without cn
   * @return {Promise}
   */
  move(filter, newDN) {
    return this.read({filter}).then((users) => {
      let movePromise = (oldDn, newDn) => new Promise((resolve, reject) => {
        if (oldDn === newDn) return resolve(true);
        this.client.modifyDN(oldDn, newDn, (err) => {
          if (err) return reject(err);
          resolve(true);
        });
      });

      return Promise.all(users.map((u) =>
        movePromise(u.dn, `cn=${u.cn},${newDN ? newDN : u.dn}`)
      ));
    });
  }
}

module.exports = LDAPCRUD;
