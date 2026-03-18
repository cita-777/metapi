import { describe, expect, it } from 'vitest';

import {
  canonicalAttachmentFromInputFileBlock,
  canonicalAttachmentToNormalizedInputFile,
} from './attachments.js';

describe('canonical attachment helpers', () => {
  it('normalizes input_file blocks and prefers file_data over file_url and file_id', () => {
    const attachment = canonicalAttachmentFromInputFileBlock({
      type: 'input_file',
      file_data: 'data:application/pdf;base64,QUJD',
      file_url: 'https://example.com/brief.pdf',
      file_id: 'file_ignored',
      filename: 'brief.pdf',
    });

    expect(attachment).toEqual({
      kind: 'file',
      sourceType: 'input_file',
      fileData: 'data:application/pdf;base64,QUJD',
      filename: 'brief.pdf',
      mimeType: 'application/pdf',
    });

    expect(canonicalAttachmentToNormalizedInputFile(attachment!)).toEqual({
      sourceType: 'input_file',
      fileData: 'data:application/pdf;base64,QUJD',
      filename: 'brief.pdf',
      mimeType: 'application/pdf',
      hadDataUrl: true,
    });
  });

  it('preserves file_url when no file_data exists', () => {
    const attachment = canonicalAttachmentFromInputFileBlock({
      type: 'file',
      file: {
        file_url: 'https://example.com/report.json',
        filename: 'report.json',
        mime_type: 'application/json',
      },
    });

    expect(attachment).toEqual({
      kind: 'file',
      sourceType: 'file',
      fileUrl: 'https://example.com/report.json',
      filename: 'report.json',
      mimeType: 'application/json',
    });
  });
});
