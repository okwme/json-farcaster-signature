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
function verifyJsonFarcasterSignatureNeynar(
  jws:
    | {
        header: string;
        payload: string;
        signature: string;
      }
    | string,
) {
  // unpack stringified JWS compact form
  if (typeof jws === 'string') {
    const [header, payload, signature] = jws.split('.');

    jws = { header, payload, signature };
  }

  const headerObj = JSON.parse(
    Buffer.from(jws.header, 'base64url').toString('utf-8'),
  ) as JFSHeader as any;
  // JWS payload can be anything. for JSON Farcaster Signature, it is JSON
  const payloadObj = JSON.parse(
    Buffer.from(jws.payload, 'base64url').toString('utf-8'),
  ) as Record<string, any>;
  // JFS signature part is encoded as hex string rather than raw bytes.
  // It's against JWS spec but it's how FIP does it ¯\_(^_^)_/¯
  const sigHexBytes = Buffer.from(jws.signature, 'base64url');
  const sigBytes = Buffer.from(sigHexBytes.toString('utf-8').slice(2), 'hex');
  // Ethereum address in a header is encoded as hex string
  const ethAddrBytes = Buffer.from(headerObj.key.slice(2), 'hex');

  // validate signature format
  if (sigBytes.length !== 65) throw new Error('signature must be 65 bytes');
  const v = sigBytes[64];
  if (v !== 27 && v !== 28) throw new Error(`Invalid recovery id: ${v}`);

  const dataCompact = [jws.header, jws.payload].join('.');
  const dataBytes = Buffer.from(dataCompact, 'utf-8');

  const recovery = sigBytes[64] - 27;
  const secpSig = secp.Signature.fromCompact(
    sigBytes.subarray(0, 64),
  ).addRecoveryBit(recovery);

  // See: https://eips.ethereum.org/EIPS/eip-191
  const ethMsg = Buffer.concat([
    Buffer.from(`\x19Ethereum Signed Message:\n${dataBytes.length}`, 'utf-8'),
    dataBytes,
  ]);

  const ethMsgHash = keccak_256(ethMsg);
  const pubKey = secpSig.recoverPublicKey(ethMsgHash).toRawBytes(false);

  // convert public key to eth address:
  // 1) remove 0x04 prefix, 2) hash, 3) take last 20 bytes
  const recoveredEthAddr = keccak_256(pubKey.subarray(1)).subarray(-20);

  console.log({
    prefix: ethMsg.toString('utf-8'),
    hash: '0x' + Buffer.from(ethMsgHash).toString('hex'),
    pubk: '0x' + Buffer.from(pubKey).toString('hex'),
    rcad: '0x' + Buffer.from(recoveredEthAddr).toString('hex'),
  });

  const valid = Buffer.from(ethAddrBytes).equals(recoveredEthAddr);

  console.log({ valid });

  return {
    valid,
    header: headerObj as JFSHeader,
    payload: payloadObj,
  };
}

const manifests = await Promise.all([
  import('./data/yoink-manifest.json', {
    with: { type: 'json' },
  }).then((v) => v.default),
  import('./data/framedl-manifest.json', {
    with: { type: 'json' },
  }).then((v) => v.default),
  import('./data/caststorage-manifest.json', {
    with: { type: 'json' },
  }).then((v) => v.default),
  import('./data/fcbattles-manifest.json', {
    with: { type: 'json' },
  }).then((v) => v.default),
]);
const [yionk, framedl, caststorage, fcbattles] = manifests;

verifyJsonFarcasterSignatureNeynar(yionk.accountAssociation);
