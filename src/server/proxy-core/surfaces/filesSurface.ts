import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { getProxyResourceOwner } from '../../middleware/auth.js';
import {
  getProxyFileByPublicIdForOwner,
  getProxyFileContentByPublicIdForOwner,
  listProxyFilesByOwner,
  saveProxyFile,
  softDeleteProxyFileByPublicIdForOwner,
} from '../../services/proxyFileStore.js';
import { ensureMultipartBufferParser, parseMultipartFormData } from '../../routes/proxy/multipart.js';
import {
  isSupportedConversationFileMimeType,
  resolveConversationFileMimeType,
} from '../../../shared/conversationFileTypes.js';

function invalidRequest(reply: FastifyReply, message: string) {
  return reply.code(400).send({ error: { message, type: 'invalid_request_error' } });
}

function notFound(reply: FastifyReply, message = 'file not found') {
  return reply.code(404).send({ error: { message, type: 'not_found_error' } });
}

function toUnixSeconds(sqlDateTime: string | null | undefined): number {
  if (!sqlDateTime) return Math.floor(Date.now() / 1000);
  const parsed = Date.parse(sqlDateTime.replace(' ', 'T') + 'Z');
  if (!Number.isFinite(parsed)) return Math.floor(Date.now() / 1000);
  return Math.floor(parsed / 1000);
}

function toFileObject(record: {
  publicId: string;
  filename: string;
  mimeType: string;
  purpose: string | null;
  byteSize: number;
  createdAt: string | null;
}) {
  return {
    id: record.publicId,
    object: 'file',
    bytes: record.byteSize,
    created_at: toUnixSeconds(record.createdAt),
    filename: record.filename,
    purpose: record.purpose || 'assistants',
    mime_type: record.mimeType,
  };
}

export async function filesProxyRoute(app: FastifyInstance) {
  ensureMultipartBufferParser(app);

  app.post('/v1/files', async (request: FastifyRequest, reply: FastifyReply) => {
    const owner = getProxyResourceOwner(request);
    if (!owner) {
      return reply.code(401).send({ error: { message: 'Missing proxy auth context', type: 'authentication_error' } });
    }

    const formData = await parseMultipartFormData(request);
    if (!formData) {
      return invalidRequest(reply, 'multipart/form-data with a file field is required');
    }

    const fileEntry = formData.get('file');
    if (!fileEntry || typeof fileEntry !== 'object' || typeof (fileEntry as File).arrayBuffer !== 'function') {
      return invalidRequest(reply, 'file field is required');
    }

    const filename = fileEntry.name || 'upload.bin';
    const mimeType = resolveConversationFileMimeType(fileEntry.type, filename);
    if (!isSupportedConversationFileMimeType(mimeType)) {
      return invalidRequest(reply, `unsupported file mime type: ${mimeType || 'application/octet-stream'}`);
    }

    const purposeValue = formData.get('purpose');
    const purpose = typeof purposeValue === 'string' && purposeValue.trim().length > 0
      ? purposeValue.trim()
      : 'assistants';
    const buffer = Buffer.from(await fileEntry.arrayBuffer());

    const saved = await saveProxyFile({
      ...owner,
      filename,
      mimeType,
      purpose,
      contentBase64: buffer.toString('base64'),
    });
    return reply.send(toFileObject(saved));
  });

  app.get('/v1/files', async (request: FastifyRequest, reply: FastifyReply) => {
    const owner = getProxyResourceOwner(request);
    if (!owner) {
      return reply.code(401).send({ error: { message: 'Missing proxy auth context', type: 'authentication_error' } });
    }
    const files = await listProxyFilesByOwner(owner);
    return reply.send({
      object: 'list',
      data: files.map((item) => toFileObject(item)),
      has_more: false,
    });
  });

  app.get<{ Params: { fileId: string } }>('/v1/files/:fileId', async (request, reply) => {
    const owner = getProxyResourceOwner(request);
    if (!owner) {
      return reply.code(401).send({ error: { message: 'Missing proxy auth context', type: 'authentication_error' } });
    }
    const file = await getProxyFileByPublicIdForOwner(request.params.fileId, owner);
    if (!file) return notFound(reply);
    return reply.send(toFileObject(file));
  });

  app.get<{ Params: { fileId: string } }>('/v1/files/:fileId/content', async (request, reply) => {
    const owner = getProxyResourceOwner(request);
    if (!owner) {
      return reply.code(401).send({ error: { message: 'Missing proxy auth context', type: 'authentication_error' } });
    }
    const file = await getProxyFileContentByPublicIdForOwner(request.params.fileId, owner);
    if (!file) return notFound(reply);
    reply.type(file.mimeType);
    reply.header('Content-Disposition', `inline; filename="${encodeURIComponent(file.filename)}"`);
    return reply.send(file.buffer);
  });

  app.delete<{ Params: { fileId: string } }>('/v1/files/:fileId', async (request, reply) => {
    const owner = getProxyResourceOwner(request);
    if (!owner) {
      return reply.code(401).send({ error: { message: 'Missing proxy auth context', type: 'authentication_error' } });
    }
    const deleted = await softDeleteProxyFileByPublicIdForOwner(request.params.fileId, owner);
    if (!deleted) return notFound(reply);
    return reply.send({
      id: request.params.fileId,
      object: 'file',
      deleted: true,
    });
  });
}
