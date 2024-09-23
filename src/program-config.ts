import {
  assert,
  Bool,
  Bytes,
  Field,
  Provable,
  PublicKey,
  Signature,
  Struct,
  Undefined,
  VerificationKey,
  type InferProvable,
  type ProvablePure,
} from 'o1js';

/**
 * TODO: program spec must be serializable
 * - can be done by defining an enum of supported base types
 */

export type { Node };
export { Attestation };

const Undefined_: ProvablePure<undefined> = Undefined;

// TODO export from o1js
const ProvableType = {
  get<A extends WithProvable<any>>(type: A): ToProvable<A> {
    return (
      (typeof type === 'object' || typeof type === 'function') &&
      type !== null &&
      'provable' in type
        ? type.provable
        : type
    ) as ToProvable<A>;
  },
};

/**
 * An attestation is:
 * - a string fully identifying the attestation type
 * - a type for public parameters
 * - a type for private parameters
 * - a type for data (which is left generic when defining attestation types)
 * - a function `verify(publicInput: Public, privateInput: Private, data: Data)` that asserts the attestation is valid
 */
type Attestation<
  Id extends string,
  PublicType extends ProvablePureType,
  PrivateType extends ProvableType,
  DataType extends ProvablePureType
> = {
  type: Id;
  public: PublicType;
  private: PrivateType;
  data: DataType;

  verify(
    publicInput: InferProvableType<PublicType>,
    privateInput: InferProvableType<PrivateType>,
    data: InferProvableType<DataType>
  ): void;
};

function defineAttestation<
  Id extends string,
  PublicType extends ProvablePureType,
  PrivateType extends ProvableType
>(config: {
  type: Id;
  public: PublicType;
  private: PrivateType;

  verify<DataType extends ProvablePureType>(
    publicInput: InferProvableType<PublicType>,
    privateInput: InferProvableType<PrivateType>,
    dataType: DataType,
    data: InferProvableType<DataType>
  ): void;
}): <DataType extends ProvablePureType>(
  data: DataType
) => Attestation<Id, PublicType, PrivateType, DataType> {
  return function attestation(dataType) {
    return {
      type: config.type,
      public: config.public,
      private: config.private,
      data: dataType,
      verify(publicInput, privateInput, data) {
        return config.verify(publicInput, privateInput, dataType, data);
      },
    };
  };
}

// dummy attestation with no proof attached
const ANone = defineAttestation({
  type: 'attestation-none',
  public: Undefined_,
  private: Undefined_,
  verify() {
    // do nothing
  },
});

// native signature
const ASignature = defineAttestation({
  type: 'attestation-signature',
  public: PublicKey, // issuer public key
  private: Signature,

  // verify the signature
  verify(issuerPk, signature, type, data) {
    let ok = signature.verify(issuerPk, ProvableType.get(type).toFields(data));
    assert(ok, 'Invalid signature');
  },
});

// TODO recursive proof
const AProof = defineAttestation({
  type: 'attestation-proof',
  public: Field as ProvablePure<Field>, // the verification key hash (TODO: make this a `VerificationKey` when o1js supports it)
  private: Struct({
    vk: VerificationKey, // the verification key
    proof: Undefined_, // the proof, TODO: make this a `DynamicProof` when o1js supports it, or by refactoring our provable type representation
  }),

  verify(vkHash, { vk, proof }, _type, data) {
    vk.hash.assertEquals(vkHash);
    // proof.verify(vk);
    // TODO we also need to somehow ensure that the proof's output type matches the data type
    // proof.publicOutput.assertEquals(data);
    throw new Error('Proof attestation not implemented');
  },
});

const Attestation = {
  none: ANone,
  proof: AProof,
  signature: ASignature,
};

const Input = {
  public: publicParameter,
  private: privateParameter,
  constant,
};

const Operation = {
  property,
  equals,
  and,
};

type Input<Data = any> =
  | Attestation<string, ProvablePureType, ProvableType, ProvablePureType<Data>>
  | { type: 'constant'; data: ProvableType<Data>; value: Data }
  | { type: 'public'; data: ProvablePureType<Data> }
  | { type: 'private'; data: ProvableType<Data> };

type Node<Data = any> =
  | Input<Data>
  | { type: 'property'; key: string; inner: Node }
  | { type: 'equals'; left: Node; right: Node }
  | { type: 'and'; left: Node<Bool>; right: Node<Bool> };

type OutputNode<Data = any> = {
  assert?: Node<Bool>;
  data?: Node<Data>;
};

function constant<DataType extends ProvableType>(
  data: DataType,
  value: InferProvableType<DataType>
): Node<InferProvableType<DataType>> {
  return { type: 'constant', data, value };
}

function publicParameter<DataType extends ProvablePureType>(
  data: DataType
): Node<InferProvable<DataType>> {
  return { type: 'public', data };
}

function privateParameter<DataType extends ProvableType>(
  data: DataType
): Node<InferProvableType<DataType>> {
  return { type: 'private', data };
}

function property<K extends string, Data extends { [key in K]: any }>(
  node: Node<Data>,
  key: K
): Node<Data[K]> {
  return { type: 'property', key, inner: node as Node<any> };
}

function equals<Data>(left: Node<Data>, right: Node<Data>): Node<Bool> {
  return { type: 'equals', left, right };
}

function and(left: Node<Bool>, right: Node<Bool>): Node<Bool> {
  return { type: 'and', left, right };
}

// TODO remove
// small inline test

const isMain = import.meta.filename === process.argv[1];
if (isMain) {
  const Bytes32 = Bytes(32);

  function example(): OutputNode<Field> {
    // inputs
    let data = Attestation.signature(Struct({ age: Field, name: Bytes32 }));
    let targetAge = Input.public(Field);
    let targetName = Input.constant(Bytes32, Bytes32.fromString('Alice'));

    // operations
    return {
      assert: Operation.and(
        Operation.equals(Operation.property(data, 'age'), targetAge),
        Operation.equals(Operation.property(data, 'name'), targetName)
      ),
      data: Operation.property(data, 'age'),
    };
  }

  console.log(example());
}

// TODO these types should be in o1js

type WithProvable<A> = { provable: A } | A;
type ProvableType<T = any, V = any> = WithProvable<Provable<T, V>>;
type ProvablePureType<T = any, V = any> = WithProvable<ProvablePure<T, V>>;
type ToProvable<A extends WithProvable<any>> = A extends {
  provable: infer P;
}
  ? P
  : A;
type InferProvableType<T extends ProvableType> = InferProvable<ToProvable<T>>;
