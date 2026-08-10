// Type declarations for bsvz-proofs (wasm module JS API).

export type Scalar = bigint | Uint8Array;
export type Point = Uint8Array; // 33-byte compressed SEC1

export const SCALAR_LEN: 32;
export const POINT_LEN: 33;

export const ErrorCode: Readonly<{
  OK: 0;
  INVALID_POINT: 1;
  INVALID_ARG: 2;
  OUT_OF_MEMORY: 3;
  PROTOCOL: 4;
}>;

export class ProofError extends Error {
  code: number;
  name: 'ProofError';
}

export interface CreateProofsOptions {
  /** Prebuilt module bytes; defaults to the bundled bsvz_proofs.wasm. */
  wasmBytes?: Uint8Array | ArrayBuffer;
}

export interface ScalarApi {
  random(): Uint8Array;
  fromBytes(b: Uint8Array): Uint8Array;
  fromInt(v: bigint | number): Uint8Array;
  /** Low 64 bits of the canonical scalar, as an unsigned BigInt. */
  toInt(s: Scalar): bigint;
  isZero(s: Scalar): boolean;
  eq(a: Scalar, b: Scalar): boolean;
  add(a: Scalar, b: Scalar): Uint8Array;
  sub(a: Scalar, b: Scalar): Uint8Array;
  mul(a: Scalar, b: Scalar): Uint8Array;
  neg(a: Scalar): Uint8Array;
  invert(a: Scalar): Uint8Array;
}

export interface PointApi {
  add(a: Point, b: Point): Uint8Array;
  sub(a: Point, b: Point): Uint8Array;
  negate(a: Point): Uint8Array;
  mul(p: Point, k: Scalar): Uint8Array;
  eq(a: Point, b: Point): boolean;
}

export interface TranscriptApi {
  sha256(data: Uint8Array): Uint8Array;
  sha256d(data: Uint8Array): Uint8Array;
  challenge(label: string | Uint8Array, points: Point[], scalars: Scalar[]): Uint8Array;
}

export interface GeneratorsApi {
  hashToPoint(domain: string | Uint8Array): Uint8Array;
  vector(domain: string | Uint8Array, n: number): Uint8Array;
  G(): Uint8Array;
  H(): Uint8Array;
  BP_U(): Uint8Array;
}

export interface PedersenApi {
  commit(value: Scalar, blinding: Scalar): Uint8Array;
  commitWithGens(value: Scalar, blinding: Scalar, g: Point, h: Point): Uint8Array;
  verify(commitment: Point, value: Scalar, blinding: Scalar): boolean;
  add(a: Point, b: Point): Uint8Array;
  sub(a: Point, b: Point): Uint8Array;
}

export interface SchnorrProof {
  a: Uint8Array;
  s: Uint8Array;
}

export interface SchnorrApi {
  prove(label: string | Uint8Array, base: Point, p: Point, x: Scalar): SchnorrProof;
  verify(label: string | Uint8Array, base: Point, p: Point, a: Point, s: Scalar): boolean;
}

export interface OrProof {
  a: Uint8Array;
  e: Uint8Array;
  s: Uint8Array;
}

export interface CdsOrApi {
  size(n: number): number;
  prove(label: string | Uint8Array, base: Point, statements: Point[], trueIndex: number, witness: Scalar): OrProof;
  verify(label: string | Uint8Array, base: Point, statements: Point[], a: Uint8Array, e: Uint8Array, s: Uint8Array): boolean;
}

export interface RangeApi {
  size(bits: number): number;
  prove(value: Scalar, blinding: Scalar, bits: number): { commitment: Uint8Array; proof: Uint8Array };
  verify(commitment: Point, proof: Uint8Array, bits: number): boolean;
}

export interface MembershipApi {
  size(n: number): number;
  prove(commitment: Point, blinding: Scalar, set: Scalar[], value: Scalar): OrProof;
  verify(commitment: Point, set: Scalar[], a: Uint8Array, e: Uint8Array, s: Uint8Array): boolean;
}

export interface ConservationApi {
  prove(inputs: Point[], outputs: Point[], excess: Scalar): SchnorrProof;
  verify(inputs: Point[], outputs: Point[], a: Point, s: Scalar): boolean;
}

export interface ProofsApi {
  /** Module protocol version (currently 1). */
  version(): number;
  /** Inject host entropy (defaults to crypto.getRandomValues). Call before the first proof. */
  seed(entropy?: Uint8Array): void;
  /** Pin a deterministic RNG (test hook) so proofs are byte-for-byte reproducible. */
  setRngForTesting(seed: bigint | number): void;
  /** Restore the CSPRNG after setRngForTesting. */
  setRngForTestingOff(): void;
  /** Last error message set by the shim (empty on success). */
  lastError(): string;
  /** Allocate bytes in wasm linear memory; pair with free(). */
  alloc(len: number): number;
  /** Free a buffer from alloc(). */
  free(ptr: number, len: number): void;
  /** Raw wasm exports (zkp_* functions) for low-level use. */
  raw: WebAssembly.Exports;
  /** Current linear memory view (re-fetch after alloc: the buffer can grow). */
  memView(): Uint8Array;

  scalar: ScalarApi;
  point: PointApi;
  transcript: TranscriptApi;
  generators: GeneratorsApi;
  pedersen: PedersenApi;
  schnorr: SchnorrApi;
  cdsOr: CdsOrApi;
  range: RangeApi;
  rangeBp: RangeApi;
  membership: MembershipApi;
  conservation: ConservationApi;
}

export function createProofs(options?: CreateProofsOptions): Promise<ProofsApi>;
export default createProofs;
