const {webcrypto: {subtle}} = require('crypto')
const {Accumulator, Prover} = require('..')

describe('accumulator over secp256k1', function() {

  const {secp256k1: curve} = require('@noble/curves/secp256k1')

  describe('with optional secret', function() {

    const c = BigInt('0x154d396505ca22e65c0c5e055853715e34971edc27018657afe2817e2de41b68')

    describe('with hash name', function() {

      const hash = 'SHA-256'

      it('constructs accumulator', function() {
        const accumulator = new Accumulator(curve, hash, c)
        accumulator.should.have.property('inf').which.equals(curve.ProjectivePoint.ZERO)
        accumulator.should.have.property('n').which.equals(curve.CURVE.n)
        accumulator.should.have.property('z').which.equals(curve.ProjectivePoint.BASE)
        accumulator.should.have.property('Q').which.equals(curve.ProjectivePoint.ZERO)
        accumulator.should.have.property('i').which.is.null()
      })

      describe('add', function() {

        let accumulator

        before('constructs accumulator', function() {
          accumulator = new Accumulator(curve, hash, c)
        })

        const items = ['a', 'b', 'c']

        it('accumulates values', async function() {
          for (let item of items) {
            const update = await accumulator.add(item)
            update.should.have.property('v').which.is.an.instanceOf(curve.ProjectivePoint)
            update.should.have.property('w').which.is.an.instanceOf(curve.ProjectivePoint)
            update.should.have.property('Q').which.is.an.instanceOf(curve.ProjectivePoint)
            update.should.have.property('i').which.is.a.Number()
          }
        })

      })

      describe('del', function() {

        let accumulator

        before('constructs accumulator', function() {
          accumulator = new Accumulator(curve, hash, c)
        })

        const items = ['a', 'b', 'c']
        const updates = []

        before('accumulates values', async function() {
          for (let item of items) {
            updates.push(await accumulator.add(item))
          }
        })

        it('deletes elements', async function() {
          for (let update of updates.reverse()) {
            await accumulator.del(update)
          }
          accumulator.should.have.property('i').which.is.null()
          accumulator.Q.should.equal(curve.ProjectivePoint.ZERO)
          for (let update of updates) {
            await accumulator.verify(update).should.be.fulfilledWith(false)
          }
        })

      })

      describe('verify', function() {

        let accumulator

        before('constructs accumulator', function() {
          accumulator = new Accumulator(curve, hash, c)
        })

        const item = 'a'
        let witness

        before('accumulates values', async function() {
          witness = await accumulator.add(item)
        })

        it('verifies witnesses', async function() {
          await accumulator.verify(witness).should.be.fulfilledWith(true)
        })

      })

      describe('prove', function() {

        let accumulator

        before('constructs accumulator', function() {
          accumulator = new Accumulator(curve, hash, c)
        })

        const items = ['a', 'b', 'c']

        before('accumulates values', async function() {
          for (let item of items) {
            await accumulator.add(item)
          }
        })

        it('proves item', async function() {
          const witnesses = []
          for (let item of items) {
            witnesses.push(await accumulator.prove(item))
          }
          for (let witness of witnesses) {
            await accumulator.verify(witness).should.be.fulfilledWith(true)
          }
        })

      })

      describe('prover', function() {

        const hash = 'SHA-256'

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
          const updates = []

          before('accumulates values', async function() {
            for (let item of items) {
              updates.push(await accumulator.add(item))
            }
          })

          it('updates prover', async function() {
            for (let update of updates) {
              await prover.update(update)
            }
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
          const updates = []

          before('accumulates values', async function() {
            for (let item of items) {
              updates.push(await accumulator.add(item))
            }
          })

          before('updates prover', async function() {
            for (let update of updates) {
              await prover.update(update)
            }
          })

          it('computes witnesses', async function() {
            const witnesses = []
            for (let item of items) {
              witnesses.push(await prover.prove(item))
            }
            for (let i = 0; i < items.length; i++) {
              witnesses[i].should.have.property('d').which.equals(items[i])
              witnesses[i].should.have.property('v').which.is.an.instanceOf(curve.ProjectivePoint)
              witnesses[i].should.have.property('w').which.is.an.instanceOf(curve.ProjectivePoint)
              await accumulator.verify(witnesses[i]).should.be.fulfilledWith(true)
            }
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
          const updates = []

          before('accumulates values', async function() {
            for (let item of items) {
              updates.push(await accumulator.add(item))
            }
          })

          before('updates prover', async function() {
            for (let update of updates) {
              await prover.update(update)
            }
          })

          it('deletes elements', async function() {
            for (let i = updates.length - 1; i > 0; i--) {
              prover.update(await accumulator.del(updates[i]))
              prover.A.length.should.equal(i + 1)
            }
            const item = items[0]
            const witness = await prover.prove(item)
            await accumulator.verify(witness).should.be.fulfilledWith(true)
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
          const updates = []

          before('accumulates values', async function() {
            for (let item of items) {
              updates.push(await accumulator.add(item))
            }
          })

          before('updates prover', async function() {
            for (let update of updates) {
              await prover.update(update)
            }
          })

          const witnesses = []

          before('computes witnesses', async function() {
            for (let item of items) {
              witnesses.push(await prover.prove(item))
            }
          })

          it('verifies witnesses', async function() {
            for (let witness of witnesses) {
              await prover.verify(witness).should.be.fulfilledWith(true)
            }
          })

        })

      })

    })

    describe('with hash function', function() {

      const hash = async d => await subtle.digest('SHA-256', d)
      const items = ['a', 'b', 'c']

      it('accumulates, proves, and verifies', async function() {
        const accumulator = new Accumulator(curve, hash)
        const prover = new Prover(curve, hash)
        for (let item of items) {
          await prover.update(await accumulator.add(item))
        }
        const witnesses = []
        for (let item of items) {
          witnesses.push(await prover.prove(item))
        }
        for (let witness of witnesses) {
          await accumulator.verify(witness).should.be.fulfilledWith(true)
        }
      })

    })

  })

  describe('with random secret', function() {

    const hash = 'SHA-256'
    const items = ['a', 'b', 'c']

    it('accumulates, proves, and verifies', async function() {
      const items = ['d', 'e', 'f']
      const accumulator = new Accumulator(curve, hash)
      const prover = new Prover(curve, hash)
      for (let item of items) {
        await prover.update(await accumulator.add(item))
      }
      const witnesses = []
      for (let item of items) {
        witnesses.push(await prover.prove(item))
      }
      for (let witness of witnesses) {
        await accumulator.verify(witness).should.be.fulfilledWith(true)
      }
    })

  })

})
