import { createPublicClient, http } from 'viem';
import { optimism } from 'viem/chains';

const viemClient = createPublicClient({
  chain: optimism,
  transport: http(),
});

async function verifyJsonFarcasterSignatureNeynar(jws: {
  header: string;
  payload: string;
  signature: string;
}) {
  // unpack stringified JWS compact form
  if (typeof jws === 'string') {
    const [header, payload, signature] = jws.split('.');

    jws = { header, payload, signature };
  }

  const headerObj = JSON.parse(
    Buffer.from(jws.header, 'base64url').toString('utf-8'),
  ) as any;
  // JWS payload can be anything. for JSON Farcaster Signature, it is JSON
  const payloadObj = JSON.parse(
    Buffer.from(jws.payload, 'base64url').toString('utf-8'),
  ) as Record<string, any>;
  const signatureBytes = Buffer.from(jws.signature, 'base64url');
  const custodyKeyBytes = Buffer.from(headerObj.key.slice(2), 'hex');

  if (headerObj.type !== 'custody') {
    throw new Error('Invalid JFS type');
  }

  console.log({ headerObj, payloadObj, signatureBytes, custodyKeyBytes });

  const dataCompact = [jws.header, jws.payload].join('.');
  const dataBytes = Buffer.from(dataCompact, 'utf-8');

  const valid = await viemClient.verifyMessage({
    address: headerObj.key,
    message: dataCompact,
    signature: signatureBytes,
  });

  console.log(valid);

  return {
    valid,
    header: headerObj,
    payload: payloadObj,
  };
}

const [yionk, framedl, caststorage, fcbattles] = await Promise.all([
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

verifyJsonFarcasterSignatureNeynar(yionk.accountAssociation);
