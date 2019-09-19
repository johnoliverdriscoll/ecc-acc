'use strict'
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

const Hash = tf.oneOf(tf.String, tf.Function)

/**
 * @typedef {Object} Point
 * @property {BigInteger} x The x coordinate.
 * @property {BigInteger} y The y coordinate.
 */
const Point = tf.quacksLike('Point')

/**
 * @typedef {Object} Update
 * @property {(String|Buffer)} The element.
 * @property {Object} Qi The public component.
 * @property {Point} Qi.Q The point.
 * @property {Number} Qi.i The index.
 */
const Update = tf.object({
  d: Data,
  Qi: tf.object({
    Q: Point,
    i: tf.oneOf(tf.Null, tf.Number),
  }),
})

/**
 * @typedef {Object} Witness
 * @property {(String|Buffer)} d The element.
 * @property {Point} w The witness.
 * @property {Point} Qi The upblic component.
 * @property {Number} i The index.
 */
const Witness = tf.object({
  d: Data,
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
