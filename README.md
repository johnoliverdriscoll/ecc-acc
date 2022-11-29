# ecc-acc

This is an implementation of [An Accumulator Based on Bilinear Maps and Efficient
Revocation for Anonymous Credentials](https://eprint.iacr.org/2008/539.pdf). It is
a proof-of-concept cryptographic accumulator over elliptic curves.

Features:

* __Constant time accumulation__: Updating the accumulation does not require access
to all previously accumulated values.
* __Constant size accumulation__: Components of the accumulation are constant size.
* __Trustless proofs__: An untrusted prover may compute a witness of membership
for any accumulated element without knowledge of any sensitive information.
* ~~Constant time witness updates~~: Trustless witness updates are O(n^2).

## Setup

```shell
$ git clone https://github.com/johnoliverdriscoll/ecc-acc
$ cd ecc-acc
$ npm install
```

## Tutorial

There are two classes in this module. The first is [Accumulator](#Accumulator),
which represents a trusted party that is able to add and delete elements from an
accumulation as well as verify an element's membership. Constructing an accumulator
requires the parameters for an elliptic curve and an optional secret (a random secret
is generated if you do not give it one).

```javascript
// Import an underlying elliptic curve library.
const ec = require('ecurve')
// Generate parameters for a curve.
const curve = ec.getCurveByName('secp256k1')
// An algorithm used to map data to elements in Z_q.
const hash = 'sha256'
// Construct a trusted accumulator.
const accumulator = new Accumulator(curve, hash)
```

The next class is [Prover](#Prover), which represents an untrusted party that is
able to compute proofs of membership for elements that have been accumulated. The
prover does not require knowledge of the secret stored by the accumulator.

```javascript
// Construct an untrusted prover.
const prover = new Prover(curve, hash)
```

When adding an element, the accumulator returns a witness that can be used to verify
its membership later.

```javascript
// Add an element.
const d1 = '1'
const u1 = accumulator.add(d1)
// Verify the result.
assert(accumulator.verify(u1))
```

The object returned from [Accumulator.add](#Accumulator+add) contains information that
the prover requires to compute witnesses. Pass it to [Prover.update](#Prover+update).

```javascript
// Update the prover with the result.
prover.update(u1)
```

Subsequent additions of elements invalidate the previously returned witnesses. 

```javascript
// Add a new element.
const d2 = '2'
const u2 = accumulator.add(d2)
// Verify the result.
assert(accumulator.verify(u2))
// Demonstrate that the witness for d1 is no longer valid.
assert(accumulator.verify(u1) === false)
```

As long as the prover is kept updated, it can compute valid witnesses for any
accumulated element.

```javascript
// Update the prover with the result.
prover.update(u2)
// Compute a new witness for d1.
const w1 = prover.prove(d1)
// Verify the result.
assert(accumulator.verify(w1))
```

An element can be deleted from the accumulator, which invalidates its witness.

```javascript
// Delete d1 from the accumulator.
const u3 = accumulator.del(w1)
// Demonstrate that the original witness is no longer valid.
assert(accumulator.verify(w1) === false)
```

The prover must be updated after a deletion as well.

```javascript
// Update prover with the result.
prover.update(u3)
// Compute a new witness for d2.
const w2 = prover.prove(d2)
// Verify the result.
assert(accumulator.verify(w2))
```

It will not, however, be able to prove the membership of deleted elements.

```javascript
// Compute a new witness for the deleted element.
const w3 = prover.prove(d1)
// Demonstrate that the new witness is not valid either.
assert(accumulator.verify(w3) === false)
```

# API Reference

## Accumulator

**Kind**: global class  

* [Accumulator](#Accumulator)
    * [new Accumulator(curve, H, [c])](#new_Accumulator_new)
    * [.add(d)](#Accumulator+add) ⇒ [<code>Witness</code>](#Witness)
    * [.del(update)](#Accumulator+del) ⇒ [<code>Update</code>](#Update)
    * [.verify(updateOrWitness)](#Accumulator+verify) ⇒ <code>Boolean</code>

<a name="new_Accumulator_new"></a>

### new Accumulator(curve, H, [c])
Creates a new Accumulator instance. An Accumulator is a trusted party that stores a secret and
can modify the accumulation of member elements.


| Param | Type | Description |
| --- | --- | --- |
| curve | [<code>Curve</code>](#Curve) | An object containing the curve parameters. |
| H | <code>String</code> \| <code>function</code> | The name of a hash algorithm or a function that returns a digest for an input String or Buffer. |
| [c] | [<code>BigInteger</code>](#BigInteger) | An optional secret. If not provided, a random secret is generated. |

<a name="Accumulator+add"></a>

### accumulator.add(d) ⇒ [<code>Witness</code>](#Witness)
Add an element to the accumulation.

**Kind**: instance method of [<code>Accumulator</code>](#Accumulator)  
**Returns**: [<code>Witness</code>](#Witness) - An update object that includes the data added, its witness, and the
public component. This object can be passed to [Prover.update](#Prover+update),
[Accumulator.verify](#Accumulator+update), and [Accumulator.del](#Accumulator+del).  

| Param | Type | Description |
| --- | --- | --- |
| d | <code>String</code> \| <code>Buffer</code> | The element to add. |

<a name="Accumulator+del"></a>

### accumulator.del(update) ⇒ [<code>Update</code>](#Update)
Delete an element from the accumulation.

**Kind**: instance method of [<code>Accumulator</code>](#Accumulator)  
**Returns**: [<code>Update</code>](#Update) - The updated public component. This object can be passed to
[Prover.update](#Prover+update).  

| Param | Type | Description |
| --- | --- | --- |
| update | [<code>Witness</code>](#Witness) | An object previously returned from [Accumulator.add](#Accumulator+add), [Accumulator.del](#Accumulator+del), or [Prover.prove](#Prover+prove). |

<a name="Accumulator+verify"></a>

### accumulator.verify(updateOrWitness) ⇒ <code>Boolean</code>
Verify an element is a member of the accumulation.

**Kind**: instance method of [<code>Accumulator</code>](#Accumulator)  
**Returns**: <code>Boolean</code> - True if element is a member of the accumulation; false otherwise.  

| Param | Type | Description |
| --- | --- | --- |
| updateOrWitness | [<code>Update</code>](#Update) \| [<code>Witness</code>](#Witness) | An update object returned from [Accumulator.add](#Accumulator+add) or a witness object returned from [Prover.prove](#Prover+prove). |


## Prover

**Kind**: global class  

* [Prover](#Prover)
    * [new Prover(curve, H)](#new_Prover_new)
    * [.update(updateOrWitness)](#Prover+update)
    * [.prove(d)](#Prover+prove) ⇒ [<code>Witness</code>](#Witness)
    * [.verify(updateOrWitness)](#Prover+verify) ⇒ <code>Boolean</code>

<a name="new_Prover_new"></a>

### new Prover(curve, H)
Creates a prover. A Prover is an untrusted party that receives update information from the
Accumulator and can compute witnesses for elements based on that information.


| Param | Type | Description |
| --- | --- | --- |
| curve | [<code>Curve</code>](#Curve) | An object containing the curve parameters. |
| H | <code>String</code> \| <code>function</code> | The name of a hash algorithm or a function that produces a digest for an input String or Buffer. |

<a name="Prover+update"></a>

### prover.update(updateOrWitness)
Update membership data. This must be called after any element is added or deleted from the
accumulation.

**Kind**: instance method of [<code>Prover</code>](#Prover)  

| Param | Type | Description |
| --- | --- | --- |
| updateOrWitness | [<code>Update</code>](#Update) \| [<code>Witness</code>](#Witness) | An update or witness object returned from [Accumulator.add](#Accumulator+add) or [Accumulator.del](#Accumulator+del). |

<a name="Prover+prove"></a>

### prover.prove(d) ⇒ [<code>Witness</code>](#Witness)
Compute a proof of membership for an element.

**Kind**: instance method of [<code>Prover</code>](#Prover)  
**Returns**: [<code>Witness</code>](#Witness) - An object containing the element and its witness.
This object can be passed to [Accumulator.verify](#Accumulator+verify) to verify membership,
or to [Accumulator.del](#Accumulator+del) to delete the element.  

| Param | Type | Description |
| --- | --- | --- |
| d | <code>String</code> \| <code>Buffer</code> | The element to add. |

<a name="Prover+verify"></a>

### prover.verify(updateOrWitness) ⇒ <code>Boolean</code>
Verify an element is a member of the accumulation.

**Kind**: instance method of [<code>Prover</code>](#Prover)  
**Returns**: <code>Boolean</code> - True if element is a member of the accumulation; false otherwise.  

| Param | Type | Description |
| --- | --- | --- |
| updateOrWitness | [<code>Update</code>](#Update) \| [<code>Witness</code>](#Witness) | An update object returned from [Accumulator.add](#Accumulator+add) or a witness object returned from [Prover.prove](#Prover+prove). |

