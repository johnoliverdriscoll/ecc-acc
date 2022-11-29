const bn = require('bigi')
const crypto = require('crypto')
const ec = require('ecurve')
const {Accumulator, Prover} = require('..')

describe('accumulator over secp256k1', function() {

  const curve = ec.getCurveByName('secp256k1')

  describe('with optional secret', function() {

    const c = bn.fromHex('154d396505ca22e65c0c5e055853715e34971edc27018657afe2817e2de41b68')

    describe('with hash name', function() {

      const hash = 'sha256'

      it('constructs accumulator', function() {
        const accumulator = new Accumulator(curve, hash, c)
        accumulator.should.have.property('z').which.is.an.instanceOf(ec.Point)
        accumulator.z.equals(curve.G).should.equal(true)
        accumulator.should.have.property('Q').which.equals(curve.infinity)
        accumulator.should.have.property('i').which.is.null()
      })

      describe('add', function() {

        let accumulator

        before('constructs accumulator', function() {
          accumulator = new Accumulator(curve, hash, c)
        })

        const items = ['a', 'b', 'c']

        it('accumulates values', function() {
          items.forEach((item) => {
            const update = accumulator.add(item)
            update.should.have.property('v').which.is.an.instanceOf(ec.Point)
            update.should.have.property('w').which.is.an.instanceOf(ec.Point)
            update.should.have.property('Q').which.is.an.instanceOf(ec.Point)
            update.should.have.property('i').which.is.a.Number()
            return update
          })
        })

      })

      describe('del', function() {

        let accumulator

        before('constructs accumulator', function() {
          accumulator = new Accumulator(curve, hash, c)
        })

        const items = ['a', 'b', 'c']
        let updates

        before('accumulates values', function() {
          updates = items.map(item => accumulator.add(item))
        })

        it('deletes elements', function() {
          updates.reverse().forEach((update, i) => accumulator.del(update))
          accumulator.should.have.property('i').which.is.null()
          accumulator.Q.should.equal(curve.infinity)
          updates.forEach(update => accumulator.verify(update).should.equal(false))
        })

      })

      describe('verify', function() {

        let accumulator

        before('constructs accumulator', function() {
          accumulator = new Accumulator(curve, hash, c)
        })

        const item = 'a'
        let witness

        before('accumulates values', function() {
          witness = accumulator.add(item)
        })

        it('verifies witnesses', function() {
          accumulator.verify(witness).should.equal(true)
        })

      })

      describe('prover', function() {

        const hash = 'sha256'

        it('constructor prover', function() {
          const prover = new Prover(curve, hash)
          prover.should.have.property('A').which.is.an.Array().with.lengthOf(0)
          prover.should.have.property('Q').which.is.an.Array().with.lengthOf(1)
          prover.should.have.property('i').which.is.null()
        })

        describe('update', function() {

          let accumulator

          before('constructs accumulator', function() {
            accumulator = new Accumulator(curve, hash, c)
          })

          let prover

          before('constructor prover', function() {
            prover = new Prover(curve, hash)
          })

          const items = ['a', 'b', 'c']
          let updates

          before('accumulates values', function() {
            updates = items.map(item => accumulator.add(item))
          })

          it('updates prover', function() {
            updates.forEach(update => prover.update(update))
            prover.A.length.should.equal(3)
          })

        })

        describe('prove add', function() {

          let accumulator

          before('constructs accumulator', function() {
            accumulator = new Accumulator(curve, hash, c)
          })

          let prover

          before('constructor prover', function() {
            prover = new Prover(curve, hash)
          })

          const items = ['a', 'b', 'c']
          let updates

          before('accumulates values', function() {
            updates = items.map(item => accumulator.add(item))
          })

          before('updates prover', function() {
            updates.forEach(update => prover.update(update))
          })

          it('computes witnesses', function() {
            items.map(item => prover.prove(item)).forEach((witness, i) => {
              witness.should.have.property('d').which.equals(items[i])
              witness.should.have.property('v').which.is.an.instanceOf(ec.Point)
              witness.should.have.property('w').which.is.an.instanceOf(ec.Point)
              accumulator.verify(witness).should.equal(true)
            })
          })

        })

        describe('prove del', function() {

          let accumulator

          before('constructs accumulator', function() {
            accumulator = new Accumulator(curve, hash, c)
          })

          let prover

          before('constructor prover', function() {
            prover = new Prover(curve, hash)
          })

          const items = ['a', 'b', 'c']
          let updates

          before('accumulates values', function() {
            updates = items.map(item => accumulator.add(item))
          })

          before('updates prover', function() {
            updates.forEach(update => prover.update(update))
          })

          it('deletes elements', function() {
            updates.slice(1).reverse().forEach((update, i) => {
              prover.update(accumulator.del(update))
              prover.A.length.should.equal(updates.length - i - 1)
            })
            const item = items[0]
            const witness = prover.prove(item)
            accumulator.verify(witness).should.equal(true)
          })

        })

        describe('verify', function() {

          let accumulator

          before('constructs accumulator', function() {
            accumulator = new Accumulator(curve, hash, c)
          })

          let prover

          before('constructor prover', function() {
            prover = new Prover(curve, hash)
          })

          const items = ['a', 'b', 'c']
          let updates

          before('accumulates values', function() {
            updates = items.map(item => accumulator.add(item))
          })

          before('updates prover', function() {
            updates.forEach(update => prover.update(update))
          })

          let witnesses

          before('computes witnesses', function() {
            witnesses = items.map(item => prover.prove(item))
          })

          it('verifies witnesses', function() {
            witnesses.forEach(witness => prover.verify(witness).should.equal(true))
          })

        })

      })

    })

    describe('with hash function', function() {

      const hash = d => crypto.createHash('sha256').update(d).digest()
      const items = ['a', 'b', 'c']

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
    const items = ['a', 'b', 'c']

    it('accumulates, proves, and verifies', function() {
      const items = ['d', 'e', 'f']
      const accumulator = new Accumulator(curve, hash)
      const prover = new Prover(curve, hash)
      items.map(item => accumulator.add(item)).forEach(update => prover.update(update))
      items.map(item => prover.prove(item)).forEach(witness => accumulator.verify(witness).should.equal(true))
    })

  })

})
