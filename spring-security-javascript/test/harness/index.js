/* eslint-env mocha */
'use strict'

process.env.NODE_ENV = 'test'

const chai = require('chai')

chai.use(require('chai-fs'))
chai.use(require('chai-spies'))
// dirty-chai must be loaded after the other plugins
// see https://github.com/prodatakey/dirty-chai#plugin-assertions
chai.use(require('dirty-chai'))


module.exports = { expect: chai.expect, spy: chai.spy }
