/* eslint-env mocha */
'use strict'

process.env.NODE_ENV = 'test'

const chai = require('chai')

module.exports = { expect: chai.expect, spy: chai.spy }
