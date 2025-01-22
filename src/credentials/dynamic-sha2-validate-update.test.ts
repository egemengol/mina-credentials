import { Bytes, SelfProof, ZkProgram } from 'o1js';
import {
  DynamicSHA2,
  DynamicString,
  Sha2IterationState,
  Sha2Iteration,
  Sha2FinalIteration,
} from '../dynamic.ts';
import { mapObject } from '../util.ts';

const String = DynamicString({ maxLength: 850 });
const Bytes32 = Bytes(32);

const BLOCKS_PER_ITERATION = 7;

class State extends Sha2IterationState(256) {}
class Iteration extends Sha2Iteration(256, BLOCKS_PER_ITERATION) {}
class FinalIteration extends Sha2FinalIteration(256, BLOCKS_PER_ITERATION) {}

let sha2Update = ZkProgram({
  name: 'sha2-update',
  publicOutput: State,

  methods: {
    initial: {
      privateInputs: [Iteration],
      async method(iteration: Iteration) {
        let state = State.initial();
        let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },

    recursive: {
      privateInputs: [SelfProof, Iteration],
      async method(proof: SelfProof<undefined, State>, iteration: Iteration) {
        proof.verify();
        let state = proof.publicOutput;
        let publicOutput = DynamicSHA2.update(state, iteration);
        return { publicOutput };
      },
    },

    finalize: {
      privateInputs: [SelfProof, FinalIteration],
      async method(
        proof: SelfProof<undefined, State>,
        finalIteration: FinalIteration
      ) {
        proof.verify();
        let state = proof.publicOutput;
        let stateOut = DynamicSHA2.finalizeOnly(state, finalIteration);
        return { publicOutput: stateOut };
      },
    },
  },
});

class UpdateProof extends ZkProgram.Proof(sha2Update) {}

let sha2Validate = ZkProgram({
  name: 'sha2-validate',
  publicOutput: Bytes32,

  methods: {
    validate: {
      privateInputs: [UpdateProof, String],
      async method(proof: UpdateProof, payload: DynamicString) {
        proof.verify();
        const state = proof.publicOutput;
        // Validate the commitment with the original string
        const digest = DynamicSHA2.validate(256, state, payload);

        return { publicOutput: digest };
      },
    },
  },
});

console.log('Analyzing sha2Update methods...');
console.log(mapObject(await sha2Update.analyzeMethods(), (m) => m.summary()));
console.log('Analyzing sha2Validate methods...');
console.log(mapObject(await sha2Validate.analyzeMethods(), (m) => m.summary()));

let longString = String.from('hello world!'.repeat(Math.floor(850 / 12)));
console.log('String length:', longString.toString().length);

let { iterations, final } = DynamicSHA2.split(
  256,
  BLOCKS_PER_ITERATION,
  longString
);

console.log('Number of iterations (including final):', iterations.length + 1);

console.time('Compile sha2Update');
await sha2Update.compile();
console.timeEnd('Compile sha2Update');

console.time('Compile sha2Validate');
await sha2Validate.compile();
console.timeEnd('Compile sha2Validate');

let [first, ...rest] = iterations;

console.time('Proof (initial)');
// @ts-ignore
let { proof } = await sha2Update.initial(first);
console.timeEnd('Proof (initial)');

for (let index = 0; index < rest.length; index++) {
  const iteration = rest[index];
  console.time(`Proof (recursive step ${index + 1})`);
  // @ts-ignore
  ({ proof } = await sha2Update.recursive(proof, iteration));
  console.timeEnd(`Proof (recursive step ${index + 1})`);
}

console.time('Proof (finalize)');
let { proof: finalizeProof } = await sha2Update.finalize(proof, final);
console.timeEnd('Proof (finalize)');

console.time('Proof (validate)');
let { proof: finalProof } = await sha2Validate.validate(
  finalizeProof,
  longString
);
console.timeEnd('Proof (validate)');

console.log('Public output:', finalProof.publicOutput.toHex());

console.log('Expected hash:', DynamicSHA2.hash(256, longString).toHex());
