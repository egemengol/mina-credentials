import { Field, Poseidon, PrivateKey, Proof, PublicKey, Struct } from 'o1js';
import {
  Spec,
  type Input,
  type Claims,
  type PublicInputs,
} from './program-spec.ts';
import { createProgram, type Program } from './program.ts';
import {
  signCredentials,
  type CredentialSpec,
  type StoredCredential,
} from './credential.ts';
import { assert } from './util.ts';
import { generateContext, computeContext } from './context.ts';
import { NestedProvable } from './nested.ts';
import {
  convertSpecToSerializable,
  serializeInputContext,
  serializeNestedProvableValue,
} from './serialize-spec.ts';
import {
  convertSpecFromSerializable,
  deserializeInputContext,
  deserializeNestedProvableValue,
} from './deserialize-spec.ts';

export {
  PresentationRequest,
  Presentation,
  type ZkAppInputContext,
  type HttpsInputContext,
  ZkAppRequest,
  HttpsRequest,
};

type PresentationRequestType = 'no-context' | 'zk-app' | 'https';

type PresentationRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>,
  RequestType extends PresentationRequestType = PresentationRequestType,
  InputContext = any,
  WalletContext = any
> = {
  type: RequestType;
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: InputContext;

  deriveContext(
    inputContext: InputContext,
    walletContext: WalletContext
  ): Field;
};

const PresentationRequest = {
  noContext<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>
  ): NoContextRequest<Output, Inputs> {
    return {
      type: 'no-context',
      spec,
      claims,
      inputContext: undefined,
      deriveContext: () => Field(0),
    };
  },

  zkApp<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>,
    context: { presentationCircuitVKHash: Field; action: Field }
  ) {
    // generate random nonce on "the server"
    let serverNonce = Field.random();

    return ZkAppRequest({
      spec,
      claims,
      inputContext: {
        ...context,
        type: 'zk-app',
        serverNonce,
        claims: hashClaims(claims),
      },
    });
  },

  https<Output, Inputs extends Record<string, Input>>(
    spec: Spec<Output, Inputs>,
    claims: Claims<Inputs>,
    context: { presentationCircuitVKHash: Field; action: string }
  ) {
    // generate random nonce on "the server"
    let serverNonce = Field.random();

    return HttpsRequest({
      spec,
      claims,
      inputContext: {
        ...context,
        type: 'https',
        serverNonce,
        claims: hashClaims(claims),
      },
    });
  },

  toJSON(request: PresentationRequest) {
    let json = {
      type: request.type,
      spec: convertSpecToSerializable(request.spec),
      claims: serializeNestedProvableValue(request.claims),
      inputContext: serializeInputContext(request.inputContext),
    };
    return JSON.stringify(json);
  },

  fromJSON<
    R extends RequestFromType<any, any, K>,
    K extends PresentationRequestType = PresentationRequestType
  >(expectedType: K, json: string): R {
    let parsed = JSON.parse(json);
    let request = requestFromJson(parsed);
    assert(
      request.type === expectedType,
      `Expected ${expectedType} request, got ${request.type}`
    );
    return request as any;
  },
};

function requestFromJson(
  request: { type: PresentationRequestType } & Record<string, any>
) {
  let spec = convertSpecFromSerializable(request.spec);
  let claims = deserializeNestedProvableValue(request.claims);

  switch (request.type) {
    case 'no-context':
      return PresentationRequest.noContext(spec, claims);
    case 'zk-app': {
      const inputContext: any = deserializeInputContext(request.inputContext);
      return ZkAppRequest({ spec, claims, inputContext });
    }
    case 'https': {
      const inputContext: any = deserializeInputContext(request.inputContext);
      return HttpsRequest({ spec, claims, inputContext });
    }
    default:
      throw Error(`Invalid presentation request type: ${request.type}`);
  }
}

type Presentation<Output, Inputs extends Record<string, Input>> = {
  version: 'v0';
  claims: Claims<Inputs>;
  outputClaim: Output;
  proof: Proof<PublicInputs<Inputs>, Output>;
};

type Output<R> = R extends PresentationRequest<infer O> ? O : never;
type Inputs<R> = R extends PresentationRequest<any, infer I> ? I : never;
type WalletContext<R> = R extends PresentationRequest<
  any,
  any,
  any,
  any,
  infer W
>
  ? W
  : never;

const Presentation = {
  async compile<R extends PresentationRequest>(
    request: R
  ): Promise<R & { program: Program<Output<R>, Inputs<R>> }> {
    let program: Program<Output<R>, Inputs<R>> = (request as any).program ??
    createProgram(request.spec);
    await program.compile();
    return { ...request, program };
  },

  create: createPresentation,
};

async function createPresentation<R extends PresentationRequest>(
  ownerKey: PrivateKey,
  {
    request,
    walletContext,
    credentials,
  }: {
    request: R;
    walletContext: WalletContext<R>;
    credentials: (StoredCredential & { key?: string })[];
  }
): Promise<Presentation<Output<R>, Inputs<R>>> {
  let context = request.deriveContext(request.inputContext, walletContext);
  let { program } = await Presentation.compile(request);

  let credentialsNeeded = Object.entries(request.spec.inputs).filter(
    (c): c is [string, CredentialSpec] => c[1].type === 'credential'
  );
  let credentialsUsed = pickCredentials(
    credentialsNeeded.map(([key]) => key),
    credentials
  );
  let ownerSignature = signCredentials(
    ownerKey,
    context,
    ...credentialsNeeded.map(([key, input]) => ({
      ...credentialsUsed[key]!,
      credentialType: input,
    }))
  );

  let proof = await program.run({
    context,
    claims: request.claims as any,
    ownerSignature,
    credentials: credentialsUsed as any,
  });

  return {
    version: 'v0',
    claims: request.claims as any,
    outputClaim: proof.publicOutput,
    proof,
  };
}

function pickCredentials(
  credentialsNeeded: string[],
  [...credentials]: (StoredCredential & { key?: string })[]
): Record<string, StoredCredential> {
  let credentialsUsed: Record<string, StoredCredential> = {};
  let credentialsStillNeeded: string[] = [];

  for (let key of credentialsNeeded) {
    let i = credentials.findIndex((c) => c.key === key);
    if (i === -1) {
      credentialsStillNeeded.push(key);
      continue;
    } else {
      credentialsUsed[key] = credentials[i]!;
      credentials.splice(i, 1);
    }
  }
  let i = 0;
  for (let credential of credentials) {
    if (credentialsStillNeeded.length === 0) break;
    credentialsUsed[credentialsStillNeeded.shift()!] = credential;
    i++;
  }
  assert(
    credentialsStillNeeded.length === 0,
    `Missing credentials: ${credentialsStillNeeded.join(', ')}`
  );
  return credentialsUsed;
}

// specific types of requests

type RequestFromType<
  Output,
  Inputs extends Record<string, Input>,
  Type extends PresentationRequestType
> = Type extends 'no-context'
  ? NoContextRequest<Output, Inputs>
  : Type extends 'zk-app'
  ? ZkAppRequest<Output, Inputs>
  : Type extends 'https'
  ? HttpsRequest<Output, Inputs>
  : never;

type NoContextRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<Output, Inputs, 'no-context', undefined, undefined>;

type BaseInputContext = {
  presentationCircuitVKHash: Field;
  serverNonce: Field;
  claims: Field;
};

type ZkAppInputContext = BaseInputContext & {
  type: 'zk-app';
  action: Field;
};

type ZkAppRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<
  Output,
  Inputs,
  'zk-app',
  ZkAppInputContext,
  { verifierIdentity: PublicKey }
>;

function ZkAppRequest<Output, Inputs extends Record<string, Input>>(request: {
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: ZkAppInputContext;
}): ZkAppRequest<Output, Inputs> {
  return {
    type: 'zk-app',
    ...request,

    deriveContext(inputContext, walletContext) {
      // generate random nonce in the wallet
      const clientNonce = Field.random();

      const context = computeContext({
        ...inputContext,
        ...walletContext,
        clientNonce,
      });
      return generateContext(context);
    },
  };
}

type HttpsInputContext = BaseInputContext & {
  type: 'https';
  action: string;
};

type HttpsRequest<
  Output = any,
  Inputs extends Record<string, Input> = Record<string, Input>
> = PresentationRequest<
  Output,
  Inputs,
  'https',
  HttpsInputContext,
  { verifierIdentity: string }
>;

function HttpsRequest<Output, Inputs extends Record<string, Input>>(request: {
  spec: Spec<Output, Inputs>;
  claims: Claims<Inputs>;
  inputContext: HttpsInputContext;
}): HttpsRequest<Output, Inputs> {
  return {
    type: 'https',
    ...request,

    deriveContext(inputContext, walletContext) {
      // generate random nonce in the wallet
      const clientNonce = Field.random();

      const context = computeContext({
        ...inputContext,
        ...walletContext,
        clientNonce,
      });
      return generateContext(context);
    },
  };
}

function hashClaims(claims: Claims<any>) {
  let claimsType = NestedProvable.fromValue(claims);
  let claimsFields = Struct(claimsType).toFields(claims);
  return Poseidon.hash(claimsFields);
}
