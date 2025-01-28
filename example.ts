import { verifyJsonFarcasterSignature } from './jfs.ts';

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
  import('./data/invalid-manifest.json', {
    with: { type: 'json' },
  }).then((v) => v.default),
]);

manifests.forEach((manifest) => {
  const { valid, payload } = verifyJsonFarcasterSignature(
    manifest.accountAssociation,
  );

  console.log(
    `Farcaster Manifest for ${payload.domain} is ${valid ? 'valid' : 'INVALID'}`,
  );
});
