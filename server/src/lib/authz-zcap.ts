import { createDocumentLoader } from "dzcap/document-loader";
import { isDidKey } from "dzcap/did";
import { parseRootZcapUrn, urlWithProtocol } from "hono-zcap";
import type { DID } from "dzcap/did";
import type { IDocumentLoader } from "dzcap/invocation-http-signature";
import type { ISpace } from "wallet-attached-storage-database/types";
import type { IZcapCapability } from "dzcap/zcap-invocation-request";
// @ts-expect-error no types
import { verifyCapabilityInvocation as dbVerifyCapabilityInvocation } from '@digitalbazaar/http-signature-zcap-verify';
// @ts-expect-error no types
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { getVerifierForKeyId } from '@did.coop/did-key-ed25519/verifier';

function getSpaceRootUrl(url: string): string {
  const match = url.match(/^(https?:\/\/[^/]+\/space\/[^/]+)/);
  if (!match) {
    throw new Error(`Could not determine space root from url: ${url}`);
  }
  return match[1];
}

async function mockVerifyCapabilityInvocation(
  request: Request,
  options: {
    documentLoader: IDocumentLoader;
    expectedTarget: string;
    expectedRootCapability: string | IZcapCapability[];
    expectedAction?: string;
  }
) {
  const url = new URL(request.url);
  url.protocol = 'https:';
  const normalizedUrl = url.toString();

  const expectedTarget = new URL(options.expectedTarget);
  expectedTarget.protocol = 'https:'; // should already be https
  // no trailing slash on root
  if (expectedTarget.pathname.endsWith('/')) expectedTarget.pathname = expectedTarget.pathname.slice(0, -1);
  const spaceRoot = expectedTarget.toString();

  const expectedAction = options.expectedAction || request.method;
  if (expectedAction !== request.method) {
    throw new Error(`Expected action ${expectedAction}, got ${request.method}`);
  }

  const verification = await dbVerifyCapabilityInvocation({
    url: normalizedUrl,
    method: request.method,
    suite: new Ed25519Signature2020(),
    headers: Object.fromEntries(request.headers as any),
    async getVerifier({ keyId }: { keyId: string }) {
      if (!keyId) throw new Error('missing keyId');
      return getVerifierForKeyId(keyId);
    },
    documentLoader: options.documentLoader,
    expectedAction,
    expectedTarget: normalizedUrl,  // strict target → will fail on child
    expectedRootCapability: options.expectedRootCapability,
    expectedHost: request.headers.get('host'),
  });
  
  if (verification.verified === true) {
    return { verified: true };
  }

  const msg = (verification.error as Error | undefined)?.message ?? '';
  const onlyMismatch =
    msg.includes('Invocation target') &&
    msg.includes('does not match capability target');

  if (onlyMismatch) {
    // same origin?
    const requestUrl = new URL(normalizedUrl);
    const rootUrl = new URL(spaceRoot);
    const sameOrigin = requestUrl.origin === rootUrl.origin;

    // path boundary check:
    // allow exact root (/space/:uuid) OR a child (/space/:uuid/...)
    const isAtRoot = requestUrl.pathname === rootUrl.pathname;
    const isUnderRoot =
      requestUrl.pathname.startsWith(rootUrl.pathname.endsWith('/')
        ? rootUrl.pathname
        : rootUrl.pathname + '/');

    if (!(sameOrigin && (isAtRoot || isUnderRoot))) {
      throw new Error(
        `Invocation target (${normalizedUrl}) is not under space root (${spaceRoot})`
      );
    }
    return { verified: true, relaxedChildOfSpace: true };
  }

  // any other error: bubble up.
  if (verification.error) throw verification.error;
  throw new Error('Capability invocation verification failed.');
}
export default async function authorizeWithZcap(
  request: Request,
  options: {
    space(): Promise<ISpace>;
    expectedTarget?: string;
    expectedAction?: string;
    expectedRootCapability?: string | IZcapCapability[];
    documentLoader?: IDocumentLoader;
    onVerificationError?: (error: unknown) => void;
    resolveRootZcap?: (
      urn: `urn:zcap:root:${string}`
    ) => Promise<{
      controller?: DID;
      "@context": "https://w3id.org/zcap/v1";
      id: string;
      invocationTarget: string;
    }>;
    required?: boolean;
    trustHeaderXForwardedProto?: boolean;
  }
): Promise<boolean> {
  const defaultResolveRootZcap = async (urn: `urn:zcap:root:${string}`) => {
    const { invocationTarget } = parseRootZcapUrn(urn);
    const space = await options.space();
    const controller = space.controller;
    if (!controller || !isDidKey(controller)) {
      throw new Error(`unable to resolve controller did:key for root zcap urn`, {
        cause: { urn },
      });
    }
    return {
      "@context": "https://w3id.org/zcap/v1" as const,
      invocationTarget,
      id: urn,
      controller,
    };
  };

  const resolveRootZcap = options.resolveRootZcap ?? defaultResolveRootZcap;

  const documentLoader =
    options.documentLoader ||
    createDocumentLoader(async (url) => {
      if (url.startsWith(`urn:zcap:root:`)) {
        const resolved = await resolveRootZcap(url as `urn:zcap:root:${string}`);
        if (!resolved) {
          throw new Error(
            `resolveRootZcap returned falsy when resolving ${url}`,
            { cause: { url } }
          );
        }
        return {
          document: resolved,
          documentUrl: url,
        };
      }
      throw new Error(`unable to load document ` + url);
    });

  let hasProvenSufficientAuthorization = false;
  
  if (!request.headers.has("capability-invocation")) {
    console.warn('No capability-invocation header found, returning false')
    return false;
  }
  try {
    const spaceRoot = getSpaceRootUrl(request.url);

    const result = await mockVerifyCapabilityInvocation(request, {
      expectedTarget: options.expectedTarget ?? spaceRoot,
      expectedAction: options.expectedAction ?? request.method,
      expectedRootCapability:
        options.expectedRootCapability ??
        `urn:zcap:root:${encodeURIComponent(spaceRoot)}`,
      documentLoader,
    });
    hasProvenSufficientAuthorization = true;
  } catch (error) {
    console.debug('Error while verifying capability invocation:', error)
    options.onVerificationError?.(error);
    return false;
  }

  return hasProvenSufficientAuthorization;
}
