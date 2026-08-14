'use strict'

// Standalone semantic replay of Fastify PR 6838's method normalization change.
const assert = require('node:assert/strict')

const routes = new Map([['GET /artists/:artistId', { params: { artistId: ':artistId' } }]])

function beforeFindRoute (options) {
  return routes.get(`${options.method} ${options.url || ''}`) ?? null
}

function afterFindRoute (options) {
  return routes.get(`${options.method?.toUpperCase() ?? ''} ${options.url || ''}`) ?? null
}

const request = { method: 'get', url: '/artists/:artistId' }
const beforeDefectObserved = beforeFindRoute(request) === null
const afterResult = afterFindRoute(request)
const afterExpectationPassed = afterResult?.params.artistId === ':artistId'
const missingMethodStillNull = afterFindRoute({ url: request.url }) === null

assert.equal(beforeDefectObserved, true)
assert.equal(afterExpectationPassed, true)
assert.equal(missingMethodStillNull, true)

process.stdout.write(JSON.stringify({
  case_id: 'fastify-6838',
  language: 'JavaScript',
  before_defect_observed: beforeDefectObserved,
  after_expectation_passed: afterExpectationPassed && missingMethodStillNull,
  scope: 'standalone semantic micro-replay; not the Fastify test suite'
}) + '\n')
