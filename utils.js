'use strict';

/**
 * Generate password hash for Active Directory
 * @param {String} pwd (clear password)
 * @return {String} (hashed password)
 */
let encodePassword = (pwd) => new Buffer(`"${pwd}"`, 'utf16le').toString();

module.exports = {encodePassword};
