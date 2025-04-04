import { keccak_256 } from '@noble/hashes/sha3';
import * as secp from '@noble/secp256k1';

type JFSHeader = {
  fid: string;
  type: string;
  key: string;
};

/**
 * Verifies JSON Farcaster Signature (JFS), a malformed subset
 * of JSON Web Signature (JWS)
 * Accepts both compact JWS string and JWS object.
 * Signature segment is encoded as 0x hex string.
 *
 * See original spec:
 * https://github.com/farcasterxyz/protocol/discussions/208
 */
export function verifyJsonFarcasterSignature(
  jws:
    | {
        header: string;
        payload: string;
        signature: string;
      }
    | string
) {
  // unpack stringified JWS compact form
  if (typeof jws === 'string') {
    const [header, payload, signature] = jws.split('.');

    jws = { header, payload, signature };
  }

  const headerObj = JSON.parse(
    Buffer.from(jws.header, 'base64url').toString('utf-8')
  ) as JFSHeader as any;
  console.log({ headerObj });
  // JWS payload can be anything. for JSON Farcaster Signature, it is JSON
  const payloadObj = JSON.parse(
    Buffer.from(jws.payload, 'base64url').toString('utf-8')
  ) as Record<string, any>;
  // JFS signature part is encoded as hex string rather than raw bytes.
  // It's against JWS spec but it's how FIP does it ¯\_(^_^)_/¯
  const sigBytes = Buffer.from(jws.signature, 'base64url');

  // Create a new buffer with 65 bytes (original 64 + 1 recovery byte)
  const fullSigBytes = Buffer.alloc(65);
  sigBytes.copy(fullSigBytes, 0); // Copy original signature into new buffer
  fullSigBytes[64] = 27; // Add recovery bit (try 28 if 27 doesn't work)

  // Now fullSigBytes should be 65 bytes
  // console.log({ fullSigBytes });

  // public key is a header
  // const ethAddrBytes = Buffer.from(headerObj.key.slice(2), 'hex');

  // validate signature formatf
  if (fullSigBytes.length !== 65)
    throw new Error(
      'signature must be 65 bytes but received ' + fullSigBytes.length
    );
  const v = fullSigBytes[64];
  if (v !== 27 && v !== 28) throw new Error(`Invalid recovery id: ${v}`);

  const dataCompact = [jws.header, jws.payload].join('.');
  const dataBytes = Buffer.from(dataCompact, 'utf-8');

  const recovery = fullSigBytes[64] - 27;
  const secpSig = secp.Signature.fromCompact(
    fullSigBytes.subarray(0, 64)
  ).addRecoveryBit(recovery);

  // See: https://eips.ethereum.org/EIPS/eip-191
  const ethMsg = Buffer.concat([
    Buffer.from(`\x19Ethereum Signed Message:\n${dataBytes.length}`, 'utf-8'),
    dataBytes,
  ]);

  const ethMsgHash = keccak_256(ethMsg);
  // recover uncompressed key
  const pubKey = secpSig.recoverPublicKey(ethMsgHash).toRawBytes(false);

  // convert public key to eth address:
  // 1) remove 0x04 prefix, 2) hash, 3) take last 20 bytes
  // const recoveredEthAddr = keccak_256(pubKey.subarray(1)).subarray(-20);

  const valid = headerObj.key.slice(2) == Buffer.from(pubKey).toString('hex');

  return {
    valid,
    header: headerObj as JFSHeader,
    payload: payloadObj,
  };
}
