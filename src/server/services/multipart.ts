import type { FastifyInstance, FastifyRequest } from 'fastify';

type MultipartAwareFastify = FastifyInstance & {
  __metapiMultipartParserRegistered?: boolean;
};

function getContentType(request: FastifyRequest): string {
  return typeof request.headers['content-type'] === 'string'
    ? request.headers['content-type']
    : '';
}

export function ensureMultipartBufferParser(app: FastifyInstance): void {
  const target = app as MultipartAwareFastify;
  if (target.__metapiMultipartParserRegistered) return;

  app.addContentTypeParser(/^multipart\/form-data(?:;.*)?$/i, { parseAs: 'buffer' }, (_request, body, done) => {
    done(null, body);
  });

  target.__metapiMultipartParserRegistered = true;
}

export function isMultipartRequest(request: FastifyRequest): boolean {
  return /^multipart\/form-data(?:;.*)?$/i.test(getContentType(request));
}

export async function parseMultipartFormData(
  request: FastifyRequest,
): Promise<FormData | null> {
  if (!isMultipartRequest(request)) return null;
  const contentType = getContentType(request);
  const body = request.body;
  if (!Buffer.isBuffer(body) && !(body instanceof Uint8Array)) return null;

  const response = new Response(new Blob([Buffer.from(body)]), {
    headers: {
      'content-type': contentType,
    },
  });
  return response.formData();
}

export function cloneFormDataWithOverrides(
  formData: FormData,
  overrides: Record<string, string>,
): FormData {
  const next = new FormData();
  const applied = new Set<string>();

  for (const [key, value] of formData.entries()) {
    if (Object.prototype.hasOwnProperty.call(overrides, key)) {
      next.append(key, overrides[key] ?? '');
      applied.add(key);
      continue;
    }

    if (typeof value === 'string') {
      next.append(key, value);
      continue;
    }

    const fileLike = value as unknown as File;
    next.append(key, value, fileLike.name || 'upload.bin');
  }

  for (const [key, value] of Object.entries(overrides)) {
    if (applied.has(key)) continue;
    next.append(key, value);
  }

  return next;
}
