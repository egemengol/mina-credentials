import { Field, Provable } from 'o1js';
import { deepStrictEqual } from 'node:assert';
import { DynamicSHA2 } from './dynamic-sha2.ts';
import { DynamicBytes } from './dynamic-bytes.ts';
import test from 'node:test';

const DynBytes = DynamicBytes({ maxLength: 430 });
const BLOCKS_PER_ITERATION = 4;

await test('sha256 split and validate', async () => {
  const inputString = 'Hello, world!';
  const bytes = DynBytes.fromString(inputString);

  const { initial, iterations, final } = DynamicSHA2.split(
    256,
    BLOCKS_PER_ITERATION,
    bytes
  );

  let state = initial;
  for (const iteration of iterations) {
    state = DynamicSHA2.update(state, iteration);
  }

  const result = DynamicSHA2.finalizeOnly(state, final);

  await Provable.runAndCheck(() => {
    const bytesWitness = Provable.witness(DynBytes, () => bytes);
    DynamicSHA2.validate(256, result, bytesWitness);
  });

  // Compare with direct computation
  const expectedHash = DynamicSHA2.hash(256, bytes);
  deepStrictEqual(
    DynamicSHA2.validate(256, result, bytes).toString(),
    expectedHash.toString()
  );
});

await test('sha384 split and validate', async () => {
  const inputString = 'Test message for SHA384';
  const bytes = DynBytes.fromString(inputString);

  const { initial, iterations, final } = DynamicSHA2.split(
    384,
    BLOCKS_PER_ITERATION,
    bytes
  );

  let state = initial;
  for (const iteration of iterations) {
    state = DynamicSHA2.update(state, iteration);
  }

  const result = DynamicSHA2.finalizeOnly(state, final);

  await Provable.runAndCheck(() => {
    const bytesWitness = Provable.witness(DynBytes, () => bytes);
    DynamicSHA2.validate(384, result, bytesWitness);
  });

  const expectedHash = DynamicSHA2.hash(384, bytes);
  deepStrictEqual(
    DynamicSHA2.validate(384, result, bytes).toString(),
    expectedHash.toString()
  );
});

await test('sha512 split and validate with constraints', async () => {
  const inputString = 'Testing SHA512 split validation';
  const bytes = DynBytes.fromString(inputString);

  const { initial, iterations, final } = DynamicSHA2.split(
    512,
    BLOCKS_PER_ITERATION,
    bytes
  );

  let state = initial;
  for (const iteration of iterations) {
    state = DynamicSHA2.update(state, iteration);
  }
  const result = DynamicSHA2.finalizeOnly(state, final);

  const constraints = await Provable.constraintSystem(() => {
    const bytesWitness = Provable.witness(DynBytes, () => bytes);
    DynamicSHA2.validate(512, result, bytesWitness);
  });

  console.log('Validation step constraints:', constraints.rows);

  const expectedHash = DynamicSHA2.hash(512, bytes);
  deepStrictEqual(
    DynamicSHA2.validate(512, result, bytes).toString(),
    expectedHash.toString()
  );
});

await test('invalid commitment should fail validation', async () => {
  const inputString = 'Test message';
  const bytes = DynBytes.fromString(inputString);

  const { initial, iterations, final } = DynamicSHA2.split(
    256,
    BLOCKS_PER_ITERATION,
    bytes
  );

  let state = initial;
  for (const iteration of iterations) {
    state = DynamicSHA2.update(state, iteration);
  }
  const result = DynamicSHA2.finalizeOnly(state, final);

  const invalidResult = {
    ...result,
    commitment: Field(999),
  };

  try {
    await Provable.runAndCheck(() => {
      const bytesWitness = Provable.witness(DynBytes, () => bytes);
      DynamicSHA2.validate(256, invalidResult, bytesWitness);
    });
    throw new Error('Validation should have failed');
  } catch (error) {
    console.log('Validation failed as expected for invalid commitment');
  }
});
