export type ConversationFileKind = 'document' | 'image' | 'audio' | 'unknown';

export declare const CONVERSATION_DOCUMENT_ACCEPT_PARTS: string[];
export declare function inferConversationFileMimeType(filename: string | null | undefined): string;
export declare function resolveConversationFileMimeType(
  mimeType: string | null | undefined,
  filename: string | null | undefined,
): string;
export declare function classifyConversationFileMimeType(
  mimeType: string | null | undefined,
): Exclude<ConversationFileKind, 'unknown'>;
export declare function detectConversationFileKind(file: {
  filename?: string | null;
  mimeType?: string | null;
}): ConversationFileKind;
export declare function isSupportedConversationFileMimeType(mimeType: string): boolean;
export declare function buildConversationAcceptList(input: {
  document: boolean;
  image: boolean;
  audio: boolean;
}): string;
