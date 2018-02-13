/**
 * Generate password hash for Active Directory
 * @param {String} pwd (clear password)
 * @return {String} (hashed password)
 */
const encodePassword = (pwd) => new Buffer(`"${pwd}"`, 'utf16le').toString();

const isUndefined = (obj) => obj === void 0;

module.exports = {encodePassword, isUndefined};
