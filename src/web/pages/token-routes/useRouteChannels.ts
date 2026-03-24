import { useState, useCallback, useRef } from 'react';
import { api } from '../../api.js';
import { normalizeChannels } from './utils.js';
import type { RouteChannel } from './types.js';

export function useRouteChannels() {
  const [channelsByRouteId, setChannelsByRouteId] = useState<Record<number, RouteChannel[]>>({});
  const [loadingChannelsByRouteId, setLoadingChannelsByRouteId] = useState<Record<number, boolean>>({});
  const channelsByRouteIdRef = useRef(channelsByRouteId);
  channelsByRouteIdRef.current = channelsByRouteId;

  const loadChannels = useCallback(async (routeId: number, force = false) => {
    if (!force && channelsByRouteIdRef.current[routeId]) return channelsByRouteIdRef.current[routeId];
    setLoadingChannelsByRouteId((prev) => ({ ...prev, [routeId]: true }));
    try {
      const channels = await api.getRouteChannels(routeId);
      const sorted = normalizeChannels(channels || []);
      setChannelsByRouteId((prev) => ({ ...prev, [routeId]: sorted }));
      return sorted;
    } catch (error) {
      console.error(`Failed to load channels for route ${routeId}:`, error);
      throw error;
    } finally {
      setLoadingChannelsByRouteId((prev) => ({ ...prev, [routeId]: false }));
    }
  }, []);

  const invalidateChannels = useCallback((routeId?: number) => {
    setChannelsByRouteId((prev) => {
      if (routeId === undefined) {
        return {};
      }
      const next = { ...prev };
      delete next[routeId];
      return next;
    });
  }, []);

  const setChannels = useCallback((routeId: number, channels: RouteChannel[]) => {
    setChannelsByRouteId((prev) => ({ ...prev, [routeId]: channels }));
  }, []);

  return {
    channelsByRouteId,
    loadingChannelsByRouteId,
    loadChannels,
    invalidateChannels,
    setChannels,
  };
}
