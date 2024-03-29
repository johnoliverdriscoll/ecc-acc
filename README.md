# ecc-acc

This is an implementation of a cryptographic accumulator over elliptic curves.

Features:

* __Constant time accumulation__: Updating the accumulation does not require access
to all previously accumulated values.
* __Constant size accumulation__: Components of the accumulation are constant size.
* __Trustless proofs__: An untrusted prover may compute a witness of membership
for any accumulated element without knowledge of any sensitive information.
* ~~Constant time witness updates~~: Trustless witness updates are $O(n^2)$.

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
// Import an underlying elliptic curve.
const curve = require('@noble/curves/secp256k1')
// An algorithm used to map data to elements in Z_q.
const hash = 'SHA-256'
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
const u1 = await accumulator.add(d1)
// Verify the result.
assert(await accumulator.verify(u1))
```

The object returned from [Accumulator.add](#Accumulator+add) contains information that
the prover requires to compute witnesses. Pass it to [Prover.update](#Prover+update).

```javascript
// Update the prover with the result.
await prover.update(u1)
```

Subsequent additions of elements invalidate the previously returned witnesses. 

```javascript
// Add a new element.
const d2 = '2'
const u2 = await accumulator.add(d2)
// Verify the result.
assert(await accumulator.verify(u2))
// Demonstrate that the witness for d1 is no longer valid.
assert(await accumulator.verify(u1) === false)
```

As long as the prover is kept updated, it can compute valid witnesses for any
accumulated element.

```javascript
// Update the prover with the result.
await prover.update(u2)
// Compute a new witness for d1.
const w1 = await prover.prove(d1)
// Verify the result.
assert(await accumulator.verify(w1))
```

An element can be deleted from the accumulator, which invalidates its witness.

```javascript
// Delete d1 from the accumulator.
const u3 = await accumulator.del(w1)
// Demonstrate that the original witness is no longer valid.
assert(await accumulator.verify(w1) === false)
```

The prover must be updated after a deletion as well.

```javascript
// Update prover with the result.
await prover.update(u3)
// Compute a new witness for d2.
const w2 = await prover.prove(d2)
// Verify the result.
assert(await accumulator.verify(w2))
```

It will not, however, be able to prove the membership of deleted elements.

```javascript
// Compute a new witness for the deleted element.
const w3 = await prover.prove(d1)
// Demonstrate that the new witness is not valid either.
assert(await accumulator.verify(w3) === false)
```

# API Reference

## Classes

<dl>
<dt><a href="#Accumulator">Accumulator</a></dt>
<dd></dd>
<dt><a href="#Prover">Prover</a></dt>
<dd></dd>
</dl>

## Typedefs

<dl>
<dt><a href="#BigInt">BigInt</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#Curve">Curve</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#Point">Point</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#Update">Update</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#Witness">Witness</a> : <code>Object</code></dt>
<dd></dd>
<dt><a href="#WitnessUpdate">WitnessUpdate</a> : <code>Object</code></dt>
<dd></dd>
</dl>

<a name="Accumulator"></a>

## Accumulator
**Kind**: global class  

* [Accumulator](#Accumulator)
    * [new Accumulator(curve, H, [c])](#new_Accumulator_new)
    * [.add(d)](#Accumulator+add) ⇒ [<code>Promise.&lt;WitnessUpdate&gt;</code>](#WitnessUpdate)
    * [.del(witness)](#Accumulator+del) ⇒ [<code>Promise.&lt;Update&gt;</code>](#Update)
    * [.verify(witness)](#Accumulator+verify) ⇒ <code>Promise.&lt;Boolean&gt;</code>
    * [.prove(d)](#Accumulator+prove) ⇒ [<code>Promise.&lt;Witness&gt;</code>](#Witness)

<a name="new_Accumulator_new"></a>

### new Accumulator(curve, H, [c])
Creates a new Accumulator instance. An Accumulator is a trusted party that stores a secret and
can modify the accumulation of member elements.


| Param | Type | Description |
| --- | --- | --- |
| curve | [<code>Curve</code>](#Curve) | An object containing the curve parameters. |
| H | <code>String</code> \| <code>function</code> | The name of a hash algorithm or a function that returns a digest for an input String or Buffer. |
| [c] | [<code>BigInt</code>](#BigInt) | An optional secret. If not provided, a random secret is generated. |

<a name="Accumulator+add"></a>

### accumulator.add(d) ⇒ [<code>Promise.&lt;WitnessUpdate&gt;</code>](#WitnessUpdate)
Add an element to the accumulation.

**Kind**: instance method of [<code>Accumulator</code>](#Accumulator)  
**Returns**: [<code>Promise.&lt;WitnessUpdate&gt;</code>](#WitnessUpdate) - A witness of the element's membership.  

| Param | Type | Description |
| --- | --- | --- |
| d | <code>Data</code> | The element to add. |

<a name="Accumulator+del"></a>

### accumulator.del(witness) ⇒ [<code>Promise.&lt;Update&gt;</code>](#Update)
Delete an element from the accumulation.

**Kind**: instance method of [<code>Accumulator</code>](#Accumulator)  
**Returns**: [<code>Promise.&lt;Update&gt;</code>](#Update) - The updated public component.  

| Param | Type | Description |
| --- | --- | --- |
| witness | [<code>Witness</code>](#Witness) \| [<code>WitnessUpdate</code>](#WitnessUpdate) | A witness of the element's membership. |

<a name="Accumulator+verify"></a>

### accumulator.verify(witness) ⇒ <code>Promise.&lt;Boolean&gt;</code>
Verify an element is a member of the accumulation.

**Kind**: instance method of [<code>Accumulator</code>](#Accumulator)  
**Returns**: <code>Promise.&lt;Boolean&gt;</code> - True if element is a member of the accumulation; false otherwise.  

| Param | Type | Description |
| --- | --- | --- |
| witness | [<code>Witness</code>](#Witness) \| [<code>WitnessUpdate</code>](#WitnessUpdate) | A witness of the element's membership. |

<a name="Accumulator+prove"></a>

### accumulator.prove(d) ⇒ [<code>Promise.&lt;Witness&gt;</code>](#Witness)
Compute a proof of membership for an element.

**Kind**: instance method of [<code>Accumulator</code>](#Accumulator)  
**Returns**: [<code>Promise.&lt;Witness&gt;</code>](#Witness) - A witness of the element's membership.  

| Param | Type | Description |
| --- | --- | --- |
| d | <code>Data</code> | The element to prove. |

<a name="Prover"></a>

## Prover
**Kind**: global class  

* [Prover](#Prover)
    * [new Prover(curve, H)](#new_Prover_new)
    * [.update(updateOrWitness)](#Prover+update)
    * [.prove(d)](#Prover+prove) ⇒ [<code>Promise.&lt;Witness&gt;</code>](#Witness)
    * [.verify(updateOrWitness)](#Prover+verify) ⇒ <code>Promise.&lt;Boolean&gt;</code>

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
| updateOrWitness | [<code>Update</code>](#Update) \| [<code>WitnessUpdate</code>](#WitnessUpdate) | An update or witness. |

<a name="Prover+prove"></a>

### prover.prove(d) ⇒ [<code>Promise.&lt;Witness&gt;</code>](#Witness)
Compute a proof of membership for an element.

**Kind**: instance method of [<code>Prover</code>](#Prover)  
**Returns**: [<code>Promise.&lt;Witness&gt;</code>](#Witness) - A witness of the element's membership.  

| Param | Type | Description |
| --- | --- | --- |
| d | <code>Data</code> | The element to prove. |

<a name="Prover+verify"></a>

### prover.verify(updateOrWitness) ⇒ <code>Promise.&lt;Boolean&gt;</code>
Verify an element is a member of the accumulation.

**Kind**: instance method of [<code>Prover</code>](#Prover)  
**Returns**: <code>Promise.&lt;Boolean&gt;</code> - True if element is a member of the accumulation; false otherwise.  

| Param | Type | Description |
| --- | --- | --- |
| updateOrWitness | [<code>Witness</code>](#Witness) \| [<code>WitnessUpdate</code>](#WitnessUpdate) | An update or witness. |

<a name="BigInt"></a>

## BigInt : <code>Object</code>
**Kind**: global typedef  
<a name="Curve"></a>

## Curve : <code>Object</code>
**Kind**: global typedef  
<a name="Point"></a>

## Point : <code>Object</code>
**Kind**: global typedef  
<a name="Update"></a>

## Update : <code>Object</code>
**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| d | <code>String</code> \| <code>Buffer</code> | The element. |
| z | [<code>Point</code>](#Point) | The current accumulation. |
| Q | [<code>Point</code>](#Point) | The public component. |
| i | <code>Number</code> | The index. |

<a name="Witness"></a>

## Witness : <code>Object</code>
**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| d | <code>String</code> \| <code>Buffer</code> | The element. |
| v | [<code>Point</code>](#Point) | The previous accumulation. |
| w | [<code>Point</code>](#Point) | The previous accumulation raised to the secret value. |

<a name="WitnessUpdate"></a>

## WitnessUpdate : <code>Object</code>
**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| d | <code>String</code> \| <code>Buffer</code> | The element. |
| z | [<code>Point</code>](#Point) | The current accumulation. |
| v | [<code>Point</code>](#Point) | The previous accumulation. |
| w | [<code>Point</code>](#Point) | The previous accumulation raised to the secret value. |
| Q | [<code>Point</code>](#Point) | The public component. |
| i | <code>Number</code> | The index. |

