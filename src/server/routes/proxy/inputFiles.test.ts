import { describe, expect, it, vi, beforeEach } from 'vitest';

const getProxyFileByPublicIdForOwnerMock = vi.fn();

vi.mock('../../services/proxyFileStore.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../services/proxyFileStore.js')>();
  return {
    ...actual,
    getProxyFileByPublicIdForOwner: (...args: unknown[]) => getProxyFileByPublicIdForOwnerMock(...args),
  };
});

describe('inlineLocalInputFileReferences', () => {
  beforeEach(() => {
    getProxyFileByPublicIdForOwnerMock.mockReset();
  });

  it('replaces local responses input_file ids with inline-only file_data payloads', async () => {
    getProxyFileByPublicIdForOwnerMock.mockResolvedValue({
      publicId: 'file-metapi-123',
      filename: 'report.pdf',
      mimeType: 'application/pdf',
      contentBase64: Buffer.from('%PDF-demo').toString('base64'),
    });

    const { inlineLocalInputFileReferences } = await import('./inputFiles.js');
    const result = await inlineLocalInputFileReferences(
      {
        model: 'gpt-5',
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              {
                type: 'input_file',
                file_id: 'file-metapi-123',
              },
            ],
          },
        ],
      },
      { ownerType: 'global_proxy_token', ownerId: 'global' },
    );

    expect(result).toEqual({
      model: 'gpt-5',
      input: [
        {
          type: 'message',
          role: 'user',
          content: [
            {
              type: 'input_file',
              filename: 'report.pdf',
              file_data: `data:application/pdf;base64,${Buffer.from('%PDF-demo').toString('base64')}`,
            },
          ],
        },
      ],
    });
  });

  it('replaces local OpenAI file blocks with inline payloads', async () => {
    getProxyFileByPublicIdForOwnerMock.mockResolvedValue({
      publicId: 'file-metapi-abc',
      filename: 'notes.md',
      mimeType: 'text/markdown',
      contentBase64: Buffer.from('# hello').toString('base64'),
    });

    const { inlineLocalInputFileReferences } = await import('./inputFiles.js');
    const result = await inlineLocalInputFileReferences(
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
    );

    expect(result).toEqual({
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

  it('throws 404 when a local file id cannot be resolved for the owner', async () => {
    getProxyFileByPublicIdForOwnerMock.mockResolvedValue(null);

    const { inlineLocalInputFileReferences, ProxyInputFileResolutionError } = await import('./inputFiles.js');
    await expect(inlineLocalInputFileReferences(
      {
        input: [{ type: 'message', role: 'user', content: [{ type: 'input_file', file_id: 'file-metapi-missing' }] }],
      },
      { ownerType: 'managed_key', ownerId: '9' },
    )).rejects.toBeInstanceOf(ProxyInputFileResolutionError);
  });

  it('rejects unsupported inline file mime types with a clear 400 error', async () => {
    const { inlineLocalInputFileReferences, ProxyInputFileResolutionError } = await import('./inputFiles.js');
    await expect(inlineLocalInputFileReferences(
      {
        input: [
          {
            type: 'message',
            role: 'user',
            content: [
              {
                type: 'input_file',
                filename: 'archive.exe',
                file_data: Buffer.from('MZ').toString('base64'),
              },
            ],
          },
        ],
      },
      { ownerType: 'global_proxy_token', ownerId: 'global' },
    )).rejects.toBeInstanceOf(ProxyInputFileResolutionError);
  });
});
