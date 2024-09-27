import {
  Proof,
  Field,
  PublicKey,
  PrivateKey,
  Signature,
  VerificationKey,
  ZkProgram,
  Provable,
} from 'o1js';
import {
  Attestation,
  Input,
  Node,
  Operation,
  privateInputTypes,
  publicInputTypes,
  publicOutputType,
  recombineDataInputs,
  Spec,
  splitUserInputs,
  verifyAttestations,
  type PublicInputs,
  type UserInputs,
} from './program-config.ts';
import { NestedProvable, type NestedProvableFor } from './nested.ts';

export { createProgram };

type Program<Data, Inputs extends Record<string, Input>> = {
  compile(): Promise<VerificationKey>;

  run(input: UserInputs<Inputs>): Promise<Proof<PublicInputs<Inputs>, Data>>;
};

function createProgram<S extends Spec>(
  spec: S
): Program<GetSpecData<S>, S['inputs']> {
  // 1. split spec inputs into public and private inputs
  let PublicInput = NestedProvable.get(publicInputTypes(spec));
  let PublicOutput = publicOutputType(spec);
  let PrivateInput = NestedProvable.get(privateInputTypes(spec));

  let program = ZkProgram({
    name: `todo`, // we should create a name deterministically derived from the spec, e.g. `credential-${hash(spec)}`
    publicInput: PublicInput,
    publicOutput: PublicOutput,
    methods: {
      run: {
        privateInputs: [PrivateInput],
        method(publicInput, privateInput) {
          verifyAttestations(spec, publicInput, privateInput);

          let root = recombineDataInputs(spec, publicInput, privateInput);
          let assertion = Node.eval(root, spec.logic.assert);
          let output = Node.eval(root, spec.logic.data);
          assertion.assertTrue('Program assertion failed!');
          return output;
        },
      },
    },
  });

  return {
    async compile() {
      const result = await program.compile();
      return result.verificationKey;
    },
    async run(input) {
      let { publicInput, privateInput } = splitUserInputs(spec, input);
      let result = await program.run(publicInput, privateInput);
      return result as any;
    },
  };
}

// inline test

const isMain = import.meta.filename === process.argv[1];
if (isMain) {
  let { Bytes } = await import('o1js');

  const Bytes32 = Bytes(32);
  const InputData = { age: Field, name: Bytes32 };

  // TODO always include owner pk and verify signature on it
  const spec = Spec(
    {
      signedData: Attestation.signature(InputData),
      targetAge: Input.public(Field),
      targetName: Input.constant(Bytes32, Bytes32.fromString('Alice')),
    },
    ({ signedData, targetAge, targetName }) => ({
      assert: Operation.and(
        Operation.equals(Operation.property(signedData, 'age'), targetAge),
        Operation.equals(Operation.property(signedData, 'name'), targetName)
      ),
      data: Operation.property(signedData, 'age'),
    })
  );

  function createAttestation<Data>(type: NestedProvableFor<Data>, data: Data) {
    let issuer = PrivateKey.randomKeypair();
    let signature = Signature.create(
      issuer.privateKey,
      NestedProvable.get(type).toFields(data)
    );
    return { public: issuer.publicKey, private: signature, data };
  }

  let data = { age: Field(18), name: Bytes32.fromString('Alice') };
  let signedData = createAttestation(InputData, data);

  let program = createProgram(spec);
  await program.compile();

  // input types are inferred from spec
  // TODO leverage `From<>` type to pass in inputs directly as numbers / strings etc
  let proof = await program.run({ signedData, targetAge: Field(18) });

  Provable.log({
    publicInput: proof.publicInput,
    publicOutput: proof.publicOutput,
  });

  // proof types are inferred from spec
  proof.publicInput satisfies { signedData: PublicKey; targetAge: Field };
  proof.publicOutput satisfies Field;
}

// helper

type GetSpecData<S extends Spec> = S extends Spec<infer Data, any>
  ? Data
  : never;
