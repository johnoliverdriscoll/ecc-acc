'use strict'
const {randBetween} = require('bigint-crypto-utils')
const {modInv} = require('bigint-mod-arith')
const {webcrypto: {subtle}} = require('crypto')
const assert = require('assert')
const tf = require('typeforce')
const type = require('./type')

class Accumulator {

  /**
   * Creates a new Accumulator instance. An Accumulator is a trusted party that stores a secret and
   * can modify the accumulation of member elements.
   * @param {Curve} curve An object containing the curve parameters.
   * @param {(String|function)} H The name of a hash algorithm or a function that returns a digest
   * for an input String or Buffer.
   * @param {BigInt} [c] An optional secret. If not provided, a random secret is generated.
   */
  constructor(curve, H, c) {
    tf(tf.tuple(type.Curve, type.Hash, tf.maybe(type.BigInt)), arguments)
    this.inf = curve.ProjectivePoint.ZERO
    this.g = curve.ProjectivePoint.BASE
    this.n = curve.CURVE.n
    this.H = H
    this.c = c ? c : randBetween(this.n)
    this.z = this.g
    this.Q = this.inf
    this.i = null
  }

  /**
   * Add an element to the accumulation.
   * @param {Data} d The element to add.
   * @returns {Promise<WitnessUpdate>} A witness of the element's membership.
   */
  async add(d) {
    tf(tf.tuple(type.Data), arguments)
    // Map data to e in Zq.
    const e = await map(this.H, d, this.n)
    // Create witness before updating z.
    const v = this.z
    const w = this.z.multiply(this.c)
    // Update z' = z ^ ((e + c) mod n).
    this.z = this.z.multiply((e + this.c) % this.n)
    // If Q is the point at infinity, Q = g, otherwise Q = Q ^ c.
    this.Q = this.Q.equals(this.inf) ? this.g : this.Q.multiply(this.c)
    const Q = this.Q.multiply(this.c)
    // If i is Null, i = 0, otherwise i + 1.
    this.i = this.i === null ? 0 : this.i + 1
    // Create public component.
    const {z, i} = this
    return {d, z, v, w, Q, i}
  }

  /**
   * Delete an element from the accumulation.
   * @param {(Witness|WitnessUpdate)} witness A witness of the element's membership.
   * @returns {Promise<Update>} The updated public component.
   */
  async del({d, v, w}) {
    tf(tf.tuple(type.Witness), arguments)
    // Verify element is a member.
    assert(this.verify({d, v, w}), 'Accumulator does not contain d')
    // Map data to e in Zq.
    const e = await map(this.H, d, this.n)
    // Update z' = z ^ ((e + c)^-1 mod n).
    this.z = this.z.multiply(modInv((e + this.c) % this.n, this.n))
    // If Q is g, Q = the point at infinity, otherwise Q = g ^ (c ^ -1).
    const Q = this.Q
    this.Q = this.Q.equals(this.g) ? this.inf : this.Q.multiply(modInv(this.c, this.n))
    // If i is 0, i = Null, otherwise i = i - 1.
    this.i = this.i === 0 ? null : this.i - 1
    // Create public component.
    const {z, i} = this
    return {d, z, Q, i}
  }

  /**
   * Verify an element is a member of the accumulation.
   * @param {(Witness|WitnessUpdate)} witness A witness of the element's membership.
   * @returns {Promise<Boolean>} True if element is a member of the accumulation; false otherwise.
   */
  async verify({d, v}) {
    tf(tf.tuple(type.Witness), arguments)
    // Map data to e in Zq.
    const e = await map(this.H, d, this.n)
    // Compare z and v ^ (map(e) + c mod n)
    return this.z.equals(v.multiply((e + this.c) % this.n))
  }

  /**
   * Compute a proof of membership for an element.
   * @param {Data} d The element to prove.
   * @returns {Promise<Witness>} A witness of the element's membership.
   */
  async prove(d) {
    tf(tf.tuple(type.Data), arguments)
    const e = await map(this.H, d, this.n)
    const v = this.z.multiply(modInv((e + this.c) % this.n, this.n))
    const w = this.z.multiply(modInv(e, this.n))
    return {d, v, w}
  }

}

class Prover {

  /**
   * Creates a prover. A Prover is an untrusted party that receives update information from the
   * Accumulator and can compute witnesses for elements based on that information.
   * @param {Curve} curve An object containing the curve parameters.
   * @param {(String|function)} H The name of a hash algorithm or a function that produces a
   * digest for an input String or Buffer.
   */
  constructor(curve, H) {
    tf(tf.tuple(type.Curve, type.Hash), arguments)
    this.inf = curve.ProjectivePoint.ZERO
    this.n = curve.CURVE.n
    this.H = H
    this.A = []
    this.Q = [curve.ProjectivePoint.BASE]
    this.i = null
    this.z = undefined
  }

  /**
   * Update membership data. This must be called after any element is added or deleted from the
   * accumulation.
   * @param {(Update|WitnessUpdate)} updateOrWitness An update or witness.
   */
  async update({d, z, Q, i}) {
    tf(tf.tuple(type.Update), arguments)
    // Map data to e in Zq.
    const e = await map(this.H, d, this.n)
    if (i === null || i < this.i) {
      // Delete removed element if i < current index.
      this.A = this.A.filter(v => v !== e)
    } else {
      // Add element.
      this.A.push(e)
    }
    // Add public component.
    if (i === null) {
      this.Q[1] = Q
    } else {
      this.Q[i + 1] = Q
    }
    // Update i.
    this.i = i
    // Update accumulation.
    this.z = z
  }

  /**
   * Compute a proof of membership for an element.
   * @param {Data} d The element to prove.
   * @returns {Promise<Witness>} A witness of the element's membership.
   */
  async prove(d) {
    tf(tf.tuple(type.Data), arguments)
    // Map data to e in Zq.
    const e = await map(this.H, d, this.n)
    // Collect all elements except element being proven.
    const A = this.A.filter(v => v !== e)
    // For each group size up to i, combinate elements and compute the coefficient of Qi.
    const coefficients = []
    for (let i = 0; i <= this.i; i++) {
      coefficients.push(combinate(i, A).reduce((sum, group) => {
        return (sum + group.reduce((product, e) => (product * e) % this.n, 1n)) % this.n
      }, 0n))
    }
    // Compute product of coefficients and Qis.
    let v = this.inf
    let w = this.inf
    for (let i = 0; i <= this.i; i++) {
      v = v.add(this.Q[this.i - i + 0].multiply(coefficients[i]))
      w = w.add(this.Q[this.i - i + 1].multiply(coefficients[i]))
    }
    return {d, v, w}
  }

  /**
   * Verify an element is a member of the accumulation.
   * @param {(Witness|WitnessUpdate)} updateOrWitness An update or witness.
   * @returns {Promise<Boolean>} True if element is a member of the accumulation; false otherwise.
   */
  async verify({d, v, w}) {
    tf(tf.tuple(type.Witness), arguments)
    // Map data to e in Zq.
    const e = await map(this.H, d, this.n)
    // Compare z and (v ^ map(e)) * w
    return this.z.equals(v.multiply(e).add(w))
  }

}

/**
 * Return a hex string representing the data in a buffer.
 * @param {Buffer} buffer The buffer to hexlify.
 * @returns {String} The hex representation of the buffer.
 * @private
 */
function bufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('')
}

/**
 * Maps some data to an element in the set Zq.
 * @param {String|function} H A hash function.
 * @param {Data} d The data to be mapped.
 * @param {BigInt} The group order of the curve.
 * @returns {Promise<BigInt>} The mapped element.
 * @private
 */
async function map(H, d, n) {
  tf(tf.tuple(type.Hash, type.Data, type.BigInt), arguments)
  let hash
  if (typeof(H) === 'string') {
    hash = async d => await subtle.digest(H, d)
  } else {
    hash = H
  }
  if (typeof(d) === 'string') {
    const encoder = new TextEncoder()
    d = encoder.encode(d)
  }
  // Compute digest modulo the group order.
  const buf = await hash(d)
  return BigInt('0x' + bufferToHex(buf)) % n
}

/**
 * Produces all combinations of sized groups of supplied elements.
 * @example assert.deepEqual(combinate(3, [a, b, c]), [[a, b, c]])
 * @example assert.deepEqual(combinate(2, [a, b, c]), [[a, b], [a, c], [b, c]])
 * @example assert.deepEqual(combinate(1, [a, b, c]), [[a], [b], [c]])
 * @example assert.deepEqual(combinate(0, [a, b, c]), [[]])
 * @param {Number} size The size of each group.
 * @param {Array} elements Array of elements that will be selected from when forming groups.
 * @param {Array[]} [combinations] Combinations computed so far.
 * @param {Array} [group] Group currently being combinated.
 * @returns {Array[]} Combinations of elements.
 * @private
 */
function combinate(size, elements, combinations = [], group = []) {
  tf(tf.tuple(tf.Number, tf.Array, tf.maybe(tf.Array), tf.maybe(tf.Array)), arguments)
  if (group.length < size) {
    // If group size is less than specified size, combinate on each remaining element.
    for (let i = 0; i < elements.length; i++) {
      combinate(size, elements.slice(i + 1), combinations, group.concat([elements[i]]))
    }
  } else {
    // Otherwise, push group to completed combinations collection.
    combinations.push(group)
  }
  return combinations
}

module.exports = {
  Accumulator,
  Prover,
}
