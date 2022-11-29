'use strict'
const assert = require('assert')
const bn = require('bigi')
const crypto = require('crypto')
const tf = require('typeforce')
const type = require('./type')

class Accumulator {

  /**
   * Creates a new Accumulator instance. An Accumulator is a trusted party that stores a secret and
   * can modify the accumulation of member elements.
   * @param {Curve} curve An object containing the curve parameters.
   * @param {(String|Function)} H The name of a hash algorithm or a function that returns a digest
   * for an input String or Buffer.
   * @param {BigInteger} [c] An optional secret. If not provided, a random secret is generated.
   */
  constructor({infinity, G, n}, H, c) {
    tf(tf.tuple(type.Curve, type.Hash, tf.maybe(type.BigInteger)), arguments)
    this.infinity = infinity
    this.G = G
    this.n = n
    this.H = H
    this.c = (c ? c : bn.fromBuffer(crypto.randomBytes(Math.ceil(this.n.bitLength() / 8)))).mod(this.n)
    this.z = G
    this.Q = infinity
    this.i = null
  }

  /**
   * Add an element to the accumulation.
   * @param {(String|Buffer)} d The element to add.
   * @returns {Witness} An update object that includes the data added, its witness, and the
   * public component. This object can be passed to [Prover.update](#Prover+update),
   * [Accumulator.verify](#Accumulator+update), and [Accumulator.del](#Accumulator+del).
   */
  add(d) {
    tf(tf.tuple(type.Data), arguments)
    // Map data to e in Zq.
    const e = map(this.H, d, this.n)
    // Create witness before updating z.
    const v = this.z
    const w = this.z.multiply(this.c)
    // Update z' = z ^ ((e + c) mod n).
    this.z = this.z.multiply(e.add(this.c).mod(this.n))
    // If Q is the point at infinity, Q = G, otherwise Q = Q ^ c.
    this.Q = this.Q.equals(this.infinity) ? this.G : this.Q.multiply(this.c)
    const Q = this.Q.multiply(this.c)
    // If i is Null, i = 0, otherwise i + 1.
    this.i = this.i === null ? 0 : this.i + 1
    // Create public component.
    const {z, i} = this
    return {d, z, v, w, Q, i}
  }

  /**
   * Delete an element from the accumulation.
   * @param {Witness} update An object previously returned from
   * [Accumulator.add](#Accumulator+add), [Accumulator.del](#Accumulator+del), or
   * [Prover.prove](#Prover+prove).
   * @returns {Update} The updated public component. This object can be passed to
   * [Prover.update](#Prover+update).
   */
  del({d, v, w}) {
    tf(tf.tuple(type.Witness), arguments)
    // Verify element is a member.
    assert(this.verify({d, v, w}), 'Accumulator does not contain d')
    // Map data to e in Zq.
    const e = map(this.H, d, this.n)
    // Update z' = z ^ ((e + c)^-1 mod n).
    this.z = this.z.multiply(e.add(this.c).mod(this.n).modInverse(this.n))
    // If Q is G, Q = the point at infinity, otherwise Q = G ^ (c ^ -1).
    const Q = this.Q
    this.Q = this.Q.equals(this.G) ? this.infinity : this.Q.multiply(this.c.modInverse(this.n))
    // If i is 0, i = Null, otherwise i = i - 1.
    this.i = this.i === 0 ? null : this.i - 1
    // Create public component.
    const {z, i} = this
    return {d, z, Q, i}
  }

  /**
   * Verify an element is a member of the accumulation.
   * @param {(Update|Witness)} updateOrWitness An update object returned from
   * [Accumulator.add](#Accumulator+add) or a witness object returned from
   * [Prover.prove](#Prover+prove).
   * @returns {Boolean} True if element is a member of the accumulation; false otherwise.
   */
  verify({d, v, w}) {
    tf(tf.tuple(type.Witness), arguments)
    // Map data to e in Zq.
    const e = map(this.H, d, this.n)
    // Compare z and (v ^ map(e)) * w
    return this.z.equals(v.multiply(e).add(w))
  }

}

class Prover {

  /**
   * Creates a prover. A Prover is an untrusted party that receives update information from the
   * Accumulator and can compute witnesses for elements based on that information.
   * @param {Curve} curve An object containing the curve parameters.
   * @param {(String|Function)} H The name of a hash algorithm or a function that produces a
   * digest for an input String or Buffer.
   */
  constructor({infinity, G, n}, H) {
    tf(tf.tuple(type.Curve, type.Hash), arguments)
    if (typeof(H) === 'string') {
      tf(tf.oneOf(...crypto.getHashes().map(hash => tf.value(hash))), H)
    }
    this.infinity = infinity
    this.n = n
    this.H = H
    this.A = []
    this.Q = [G]
    this.i = null
    this.z = undefined
  }

  /**
   * Update membership data. This must be called after any element is added or deleted from the
   * accumulation.
   * @param {(Update|Witness)} updateOrWitness An update or witness object returned from
   * [Accumulator.add](#Accumulator+add) or [Accumulator.del](#Accumulator+del).
   */
  update({d, z, Q, i}) {
    tf(tf.tuple(type.Update), arguments)
    // Map data to e in Zq.
    const e = map(this.H, d, this.n)
    if (i === null || i < this.i) {
      // Delete removed element if i < current index.
      this.A = this.A.filter(v => v.compareTo(e) !== 0)
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
   * @param {(String|Buffer)} d The element to add.
   * @returns {Witness} An object containing the element and its witness.
   * This object can be passed to [Accumulator.verify](#Accumulator+verify) to verify membership,
   * or to [Accumulator.del](#Accumulator+del) to delete the element.
   */
  prove(d) {
    tf(tf.tuple(type.Data), arguments)
    // Map data to e in Zq.
    const e = map(this.H, d, this.n)
    // Collect all elements except element being proven.
    const A = this.A.filter(v => v.compareTo(e) !== 0)
    // For each group size up to i, combinate elements and compute the coefficient of Qi.
    const coefficients = []
    for (let i = 0; i <= this.i; i++) {
      coefficients.push(combinate(i, A).reduce((sum, group) => {
        return sum.add(group.reduce((product, e) => product.multiply(e).mod(this.n), bn.ONE)).mod(this.n)
      }, bn.ZERO))
    }
    // Compute product of coefficients and Qis.
    let v = this.infinity
    let w = this.infinity
    for (let i = 0; i <= this.i; i++) {
      v = v.add(this.Q[this.i - i + 0].multiply(coefficients[i]))
      w = w.add(this.Q[this.i - i + 1].multiply(coefficients[i]))
    }
    return {d, v, w}
  }

  /**
   * Verify an element is a member of the accumulation.
   * @param {(Update|Witness)} updateOrWitness An update object returned from
   * [Accumulator.add](#Accumulator+add) or a witness object returned from
   * [Prover.prove](#Prover+prove).
   * @returns {Boolean} True if element is a member of the accumulation; false otherwise.
   */
  verify({d, v, w}) {
    tf(tf.tuple(type.Witness), arguments)
    // Map data to e in Zq.
    const e = map(this.H, d, this.n)
    // Compare z and (v ^ map(e)) * w
    return this.z.equals(v.multiply(e).add(w))
  }

}

/**
 * Maps some data to an element in the set Zq.
 * @param {String|Function} H A hash function.
 * @param {(String|Buffer)} d The data to be mapped.
 * @param {BigInteger} The group order of the curve.
 * @returns {BigInteger} The mapped element.
 * @private
 */
function map(H, d, n) {
  tf(tf.tuple(type.Hash, type.Data, type.BigInteger), arguments)
  let hash
  if (typeof(H) === 'string') {
    hash = d => crypto.createHash(H).update(d).digest()
  } else {
    hash = H
  }
  // Compute digest modulo the group order.
  return bn.fromBuffer(hash(d)).mod(n)
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
