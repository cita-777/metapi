import { beforeEach, describe, expect, it, vi } from 'vitest';

const getProxyFileByPublicIdForOwnerMock = vi.fn();

vi.mock('./proxyFileStore.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./proxyFileStore.js')>();
  return {
    ...actual,
    getProxyFileByPublicIdForOwner: (...args: unknown[]) => getProxyFileByPublicIdForOwnerMock(...args),
  };
});

describe('proxyInputFileResolver', () => {
  beforeEach(() => {
    getProxyFileByPublicIdForOwnerMock.mockReset();
  });

  it('preserves non-local file ids without resolving them from the local store', async () => {
    const { resolveResponsesBodyInputFiles } = await import('./proxyInputFileResolver.js');
    const body = {
      model: 'gpt-5',
      input: [
        {
          type: 'message',
          role: 'user',
          content: [
            {
              type: 'input_file',
              file_id: 'file_external_123',
            },
          ],
        },
      ],
    };

    await expect(resolveResponsesBodyInputFiles(
      body,
      { ownerType: 'global_proxy_token', ownerId: 'global' },
    )).resolves.toEqual(body);
    expect(getProxyFileByPublicIdForOwnerMock).not.toHaveBeenCalled();
  });

  it('resolves object-form responses input payloads with local file ids into inline-only uploads', async () => {
    getProxyFileByPublicIdForOwnerMock.mockResolvedValue({
      publicId: 'file-metapi-123',
      filename: 'brief.pdf',
      mimeType: 'application/pdf',
      contentBase64: Buffer.from('%PDF-local').toString('base64'),
    });

    const { resolveResponsesBodyInputFiles } = await import('./proxyInputFileResolver.js');
    await expect(resolveResponsesBodyInputFiles(
      {
        model: 'gpt-5',
        input: {
          type: 'message',
          role: 'user',
          content: [
            {
              type: 'input_file',
              file_id: 'file-metapi-123',
            },
          ],
        },
      },
      { ownerType: 'managed_key', ownerId: '9' },
    )).resolves.toEqual({
      model: 'gpt-5',
      input: {
        type: 'message',
        role: 'user',
        content: [
          {
            type: 'input_file',
            filename: 'brief.pdf',
            file_data: `data:application/pdf;base64,${Buffer.from('%PDF-local').toString('base64')}`,
          },
        ],
      },
    });
  });

  it('exports generic inline local file resolution for route-level callers', async () => {
    getProxyFileByPublicIdForOwnerMock.mockResolvedValue({
      publicId: 'file-metapi-abc',
      filename: 'notes.md',
      mimeType: 'text/markdown',
      contentBase64: Buffer.from('# hello').toString('base64'),
    });

    const { inlineLocalInputFileReferences } = await import('./proxyInputFileResolver.js');
    await expect(inlineLocalInputFileReferences(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'user',
            content: [
              {
                type: 'file',
                file: {
                  file_id: 'file-metapi-abc',
                },
              },
            ],
          },
        ],
      },
      { ownerType: 'managed_key', ownerId: '7' },
    )).resolves.toEqual({
      model: 'gpt-5',
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'file',
              file: {
                file_data: Buffer.from('# hello').toString('base64'),
                filename: 'notes.md',
                mime_type: 'text/markdown',
              },
            },
          ],
        },
      ],
    });
  });

  it('falls back from application/octet-stream to filename-based mime inference', async () => {
    const { inlineLocalInputFileReferences } = await import('./proxyInputFileResolver.js');
    await expect(inlineLocalInputFileReferences(
      {
        model: 'gpt-5',
        messages: [
          {
            role: 'user',
            content: [
              {
                type: 'file',
                file: {
                  filename: 'paper.pdf',
                  mime_type: 'application/octet-stream',
                  file_data: Buffer.from('%PDF-octet').toString('base64'),
                },
              },
            ],
          },
        ],
      },
      { ownerType: 'managed_key', ownerId: '7' },
    )).resolves.toEqual({
      model: 'gpt-5',
      messages: [
        {
          role: 'user',
          content: [
            {
              type: 'file',
              file: {
                file_data: Buffer.from('%PDF-octet').toString('base64'),
                filename: 'paper.pdf',
                mime_type: 'application/pdf',
              },
            },
          ],
        },
      ],
    });
  });
});
