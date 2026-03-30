import { describe, expect, it } from 'vitest';
import {
  buildAccountFocusPath,
  buildEventNavigationPath,
  buildSiteFocusPath,
  clearFocusParams,
  readFocusAccountIntent,
  readFocusAnnouncementId,
  readFocusSiteId,
} from './navigationFocus.js';

describe('navigationFocus helpers', () => {
  it('builds focus paths for site and account', () => {
    expect(buildSiteFocusPath(12)).toBe('/sites?focusSiteId=12');
    expect(buildSiteFocusPath(0)).toBe('/sites');
    expect(buildAccountFocusPath(34)).toBe('/accounts?focusAccountId=34');
    expect(buildAccountFocusPath(34, { openRebind: true })).toBe('/accounts?focusAccountId=34&openRebind=1');
    expect(buildAccountFocusPath(-1)).toBe('/accounts');
  });

  it('parses focus params from query string', () => {
    expect(readFocusSiteId('?focusSiteId=15')).toBe(15);
    expect(readFocusSiteId('?focusSiteId=abc')).toBeNull();
    expect(readFocusAnnouncementId('?focusAnnouncementId=21')).toBe(21);
    expect(readFocusAnnouncementId('?focusAnnouncementId=abc')).toBeNull();

    expect(readFocusAccountIntent('?focusAccountId=22&openRebind=1')).toEqual({
      accountId: 22,
      openRebind: true,
    });
    expect(readFocusAccountIntent('?focusAccountId=22&openRebind=true')).toEqual({
      accountId: 22,
      openRebind: true,
    });
    expect(readFocusAccountIntent('?focusAccountId=22')).toEqual({
      accountId: 22,
      openRebind: false,
    });
  });

  it('clears focus params but keeps other params', () => {
    expect(clearFocusParams('?focusSiteId=12&q=abc')).toBe('?q=abc');
    expect(clearFocusParams('?focusAnnouncementId=44&type=site_notice')).toBe('?type=site_notice');
    expect(clearFocusParams('?focusAccountId=2&openRebind=1&type=token')).toBe('?type=token');
    expect(clearFocusParams('?focusAccountId=2')).toBe('');
  });

  it('builds event navigation path by related entity', () => {
    expect(buildEventNavigationPath({
      relatedType: 'account',
      relatedId: 18,
      type: 'token',
    })).toBe('/accounts?focusAccountId=18&openRebind=1');

    expect(buildEventNavigationPath({
      relatedType: 'account',
      relatedId: 18,
      type: 'checkin',
    })).toBe('/accounts?focusAccountId=18');

    expect(buildEventNavigationPath({
      relatedType: 'site',
      relatedId: 9,
      type: 'status',
    })).toBe('/sites?focusSiteId=9');

    expect(buildEventNavigationPath({
      relatedType: 'site_announcement',
      relatedId: 12,
      type: 'site_notice',
    })).toBe('/site-announcements?focusAnnouncementId=12');

    expect(buildEventNavigationPath({
      relatedType: 'route',
      relatedId: null,
      type: 'proxy',
    })).toBe('/routes');

    expect(buildEventNavigationPath({
      relatedType: 'update_center',
      relatedId: null,
      type: 'status',
    })).toBe('/settings');

    expect(buildEventNavigationPath({ type: 'proxy' })).toBe('/logs');
    expect(buildEventNavigationPath({ type: 'checkin' })).toBe('/checkin');
    expect(buildEventNavigationPath({ type: 'site_notice' })).toBe('/site-announcements');
    expect(buildEventNavigationPath({})).toBe('/events');
  });
});
