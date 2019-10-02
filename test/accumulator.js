const bn = require('bigi')
const crypto = require('crypto')
const ec = require('ecurve')
const {Accumulator, Prover} = require('..')

describe('accumulator over secp256k1', function() {

  const curve = ec.getCurveByName('secp256k1')

  describe('with optional secret', function() {

    const c = bn.fromHex('154d396505ca22e65c0c5e055853715e34971edc27018657afe2817e2de41b68')
    const items = ['a', 'b', 'c']

    describe('with hash name', function() {

      const hash = 'sha256'
      let accumulator
      let prover
      let updates
      let witnesses

      it('constructs accumulator', function() {
        accumulator = new Accumulator(curve, hash, c)
        accumulator.should.have.property('z').which.is.an.instanceOf(ec.Point)
        accumulator.z.equals(curve.G).should.equal(true)
        accumulator.should.have.property('Q').which.equals(curve.infinity)
        accumulator.should.have.property('i').which.is.null()
      })

      it('constructor prover', function() {
        prover = new Prover(curve, hash)
        prover.should.have.property('A').which.is.an.Array().with.lengthOf(0)
        prover.should.have.property('Q').which.is.an.Array().with.lengthOf(0)
        prover.should.have.property('i').which.is.null()
      })

      it('accumulates values', function() {
        updates = items.map((item) => {
          const update = accumulator.add(item)
          accumulator.verify(update).should.equal(true)
          update.should.have.property('w').which.is.an.instanceOf(ec.Point)
          update.should.have.property('Qi').which.is.an.Object()
          update.Qi.should.have.property('Q').which.is.an.instanceOf(ec.Point)
          update.Qi.should.have.property('i').which.is.a.Number()
          return update
        })
      })

      it('updates prover', function() {
        updates.forEach(update => prover.update(update))
        prover.A.length.should.equal(3)
      })

      it('computes witnesses', function() {
        witnesses = items.map(item => prover.prove(item))
        witnesses.forEach((witness, i) => {
          witness.should.have.property('d').which.equals(items[i])
          witness.should.have.property('w').which.is.an.instanceOf(ec.Point)
        })
      })

      it('verifies witnesses', function() {
        witnesses.forEach(witness => accumulator.verify(witness).should.equal(true))
      })

      it('deletes elements', function() {
        updates.reverse().forEach((update, i) => {
          prover.update(accumulator.del(update))
          accumulator.verify(update).should.equal(false)
          prover.A.length.should.equal(updates.length - i - 1)
        })
        prover.should.have.property('i').which.is.null()
        accumulator.should.have.property('i').which.is.null()
        accumulator.Q.should.equal(curve.infinity)
      })

      it('fails to verify witnesses for deleted elements', function() {
        witnesses.forEach(witness => accumulator.verify(witness).should.equal(false))
      })

      it('fails to verify witness for unaccumulated elements', function() {
        items.slice(0, -1).map(item => accumulator.add(item)).forEach(update => prover.update(update))
        accumulator.verify(prover.prove(items[items.length - 1])).should.equal(false)
      })

    })

    describe('with hash function', function() {

      const hash = d => crypto.createHash('sha256').update(d).digest()

      it('accumulates, proves, and verifies', function() {
        const accumulator = new Accumulator(curve, hash)
        const prover = new Prover(curve, hash)
        items.map(item => accumulator.add(item)).forEach(update => prover.update(update))
        items.map(item => prover.prove(item)).forEach(witness => accumulator.verify(witness).should.equal(true))
      })

    })

  })

  describe('with random secret', function() {

    const hash = 'sha256'

    it('accumulates, proves, and verifies', function() {
      const items = ['d', 'e', 'f']
      const accumulator = new Accumulator(curve, hash)
      const prover = new Prover(curve, hash)
      items.map(item => accumulator.add(item)).forEach(update => prover.update(update))
      items.map(item => prover.prove(item)).forEach(witness => accumulator.verify(witness).should.equal(true))
    })

  })

})
