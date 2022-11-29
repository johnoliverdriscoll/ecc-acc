'use strict'
const crypto = require('crypto')
const tf = require('typeforce')

/**
 * @typedef {Object} BigInteger
 */
const BigInteger = tf.quacksLike('BigInteger')

/**
 * @typedef {Object} Curve
 * @property {Point} infinity The point at infinity.
 * @property {Point} G The curve generator point.
 * @property {BigInteger} n The order of the curve.
 */
const Curve = tf.quacksLike('Curve')

const Data = tf.oneOf(tf.String, tf.Buffer)

const Hash = tf.oneOf(tf.Function, ...crypto.getHashes().map(hash => tf.value(hash)))

/**
 * @typedef {Object} Point
 * @property {BigInteger} x The x coordinate.
 * @property {BigInteger} y The y coordinate.
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
  BigInteger,
  Curve,
  Data,
  Hash,
  Point,
  Update,
  Witness,
}
