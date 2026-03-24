export type RouteMode = 'pattern' | 'explicit_group';
export type RouteDecisionCandidate = {
    channelId: number;
    accountId: number;
    username: string;
    siteName: string;
    tokenName: string;
    priority: number;
    weight: number;
    eligible: boolean;
    recentlyFailed: boolean;
    avoidedByRecentFailure: boolean;
    probability: number;
    reason: string;
};
export type RouteDecision = {
    requestedModel: string;
    actualModel: string;
    matched: boolean;
    selectedChannelId?: number;
    selectedLabel?: string;
    summary: string[];
    candidates: RouteDecisionCandidate[];
};
export declare function normalizeTokenRouteMode(routeMode: unknown): RouteMode;
