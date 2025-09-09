import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020'
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020'
import { ZcapClient } from '@digitalcredentials/ezcap'

// ---- Replace with your actual zcap + appInstanceDid ----
const STORED = {
  zcap: {
    "@context": [
      "https://w3id.org/zcap/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "urn:uuid:292108ca-13d9-411c-9fed-2ce029e0303d",
    "controller": "did:key:z6Mktn8eHAKLXsxk6ZfcMMZZ5L2MVjzUybsE1cP1Szw5BnuA",
    "parentCapability": "urn:zcap:root:https%3A%2F%2Fcylinder-hospitality-correction-terrorism.trycloudflare.com%2Fspace%2F811cfec3-5cec-48aa-8943-326f7f3e08de",
    "invocationTarget": "https://cylinder-hospitality-correction-terrorism.trycloudflare.com/space/811cfec3-5cec-48aa-8943-326f7f3e08de",
    "expires": "2025-09-19T18:08:14.032Z",
    "allowedAction": [
      "GET",
      "POST",
      "PUT",
      "DELETE"
    ],
    "proof": {
      "type": "Ed25519Signature2020",
      "created": "2025-09-09T18:11:02Z",
      "verificationMethod": "did:key:z6MkvFW6i185FJPpRQXYgGzTALFAuFCyE1LUumtQrgXY2bZ7#z6MkvFW6i185FJPpRQXYgGzTALFAuFCyE1LUumtQrgXY2bZ7",
      "proofPurpose": "capabilityDelegation",
      "capabilityChain": [
        "urn:zcap:root:https%3A%2F%2Fcylinder-hospitality-correction-terrorism.trycloudflare.com%2Fspace%2F811cfec3-5cec-48aa-8943-326f7f3e08de"
      ],
      "proofValue": "z3MXHAimYMiDk6RyEGqRewHTfbWgJG9xjd6mYavfvi9jG6bVsk4M7abMRdGUofDuVirVqgWHvqkAWWEV4HR34jmHv"
    }
  },
  appInstance: {
    "controller": "did:key:z6Mktn8eHAKLXsxk6ZfcMMZZ5L2MVjzUybsE1cP1Szw5BnuA",
    "id": "did:key:z6Mktn8eHAKLXsxk6ZfcMMZZ5L2MVjzUybsE1cP1Szw5BnuA#z6Mktn8eHAKLXsxk6ZfcMMZZ5L2MVjzUybsE1cP1Szw5BnuA",
    "publicKeyMultibase": "z6Mktn8eHAKLXsxk6ZfcMMZZ5L2MVjzUybsE1cP1Szw5BnuA",
    "privateKeyMultibase": "zrv1cgFy7r4muqLWnbuFNt3grJEokzszsVEX1H89S48vYyK9RFSN3f3fr82o6bNDTp78soWxTfLTRjZDByHZVVL7pKe"
  }
}
// ----------------------------------------------------------------

async function main() {
  console.log('Starting WAS upload (local test)...')

  const { zcap, appInstance } = STORED
  console.log('Using appInstance DID:', appInstance.id)

  // signer
  const key = await Ed25519VerificationKey2020.from(appInstance)
  const invocationSigner = key.signer()

  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner,
  })

  const blob = new Blob(['Hello local WAS upload!'])

  // base = /space/:uuid
  const baseUrl = zcap.invocationTarget
  console.log('Zcap target:', baseUrl)

  // final URL = /space/:uuid/:name
  const wasUrl = `${baseUrl}/${encodeURIComponent('test-local.txt')}`
  console.log('Uploading to:', wasUrl)

  try {
    console.log('zcap:', zcap)
    console.log('Attempting upload...')

    const response = await zcapClient.request({
      url: wasUrl,
      capability: zcap,
      method: 'PUT',
      action: 'PUT',
      blob,
    })

    console.log('Upload complete!')
    console.log('Response:', response)
  } catch (err) {
    console.error('Upload failed:', err)
  }
}

main().catch(err => {
  console.error('Script crashed:', err)
  process.exit(1)
})
