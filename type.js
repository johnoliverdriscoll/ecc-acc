'use strict'
const crypto = require('crypto')
const tf = require('typeforce')

/**
 * @typedef {Object} BigInt
 */
function BigInt(x) {
  return typeof x === 'bigint'
}
BigInt.toJSON = () => 'bigint'

/**
 * @typedef {Object} Curve
 */
const Curve = tf.object({
  ProjectivePoint: tf.Function,
  CURVE: {n: BigInt},
})

const Data = tf.oneOf(tf.String, tf.Buffer)

const Hash = tf.oneOf(tf.String, tf.Function)

/**
 * @typedef {Object} Point
 */
const Point = tf.quacksLike('Point')

/**
 * @typedef {Object} Update
 * @property {(String|Buffer)} The element.
 * @property {Point} z The current accumulation.
 * @property {Point} Q The public component.
 * @property {Number} i The index.
 */
const Update = tf.object({
  d: Data,
  z: Point,
  Q: Point,
  i: tf.oneOf(tf.Null, tf.Number),
})

/**
 * @typedef {Object} Witness
 * @property {(String|Buffer)} d The element.
 * @property {Point} v The previous accumulation.
 * @property {Point} w The previous accumulation raised to the secret value.
 */
const Witness = tf.object({
  d: Data,
  v: Point,
  w: Point,
})

module.exports = {
  BigInt,
  Curve,
  Data,
  Hash,
  Point,
  Update,
  Witness,
}
