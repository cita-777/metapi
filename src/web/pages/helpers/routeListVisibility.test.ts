import { describe, expect, it } from 'vitest';
import { buildVisibleRouteList } from './routeListVisibility.js';

describe('routeListVisibility', () => {
  it('hides exact routes covered by an explicit group', () => {
    const routes = [
      {
        id: 1,
        modelPattern: 'gpt-5.5',
        displayName: null,
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: true,
      },
      {
        id: 2,
        modelPattern: 'gpt-5.5-high',
        displayName: null,
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: true,
      },
      {
        id: 3,
        modelPattern: 'gpt-5.5',
        displayName: 'gpt-5.5',
        routeMode: 'explicit_group',
        sourceRouteIds: [1, 2],
        enabled: true,
      },
    ];

    const visible = buildVisibleRouteList(
      routes,
      (pattern) => !pattern.includes('*') && !pattern.startsWith('re:'),
      (model, pattern) => {
        if (pattern.startsWith('re:')) return /^gpt-5\.5.*$/.test(model);
        return pattern === model;
      },
    );

    expect(visible.map((route) => route.id)).toEqual([3]);
  });

  it('hides exact routes covered by a regex group', () => {
    const routes = [
      {
        id: 1,
        modelPattern: 'gpt-5.5',
        displayName: null,
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: true,
      },
      {
        id: 2,
        modelPattern: 'gpt-5.5-high',
        displayName: null,
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: true,
      },
      {
        id: 3,
        modelPattern: 're:^gpt-5\\.5.*$',
        displayName: 'gpt-5.5-group',
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: true,
      },
    ];

    const visible = buildVisibleRouteList(
      routes,
      (pattern) => !pattern.includes('*') && !pattern.startsWith('re:'),
      (model, pattern) => {
        if (pattern.startsWith('re:')) return /^gpt-5\.5.*$/.test(model);
        return pattern === model;
      },
    );

    expect(visible.map((route) => route.id)).toEqual([3]);
  });

  it('keeps disabled exact routes visible when a group covers their model', () => {
    const routes = [
      {
        id: 1,
        modelPattern: 'gpt-5.5',
        displayName: null,
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: false,
      },
      {
        id: 2,
        modelPattern: 're:^gpt-5.5.*$',
        displayName: 'gpt-5-group',
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: true,
      },
    ];

    const visible = buildVisibleRouteList(
      routes,
      (pattern) => !pattern.includes('*') && !pattern.startsWith('re:'),
      (model, pattern) => pattern.startsWith('re:') && /^gpt-5\.5.*$/.test(model),
    );

    expect(visible.map((route) => route.id)).toEqual([1, 2]);
  });

  it('keeps an unnamed exact route visible when a pattern alias collides with it', () => {
    const routes = [
      {
        id: 1,
        modelPattern: 'gpt-5',
        displayName: null,
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: true,
      },
      {
        id: 2,
        modelPattern: 're:^gpt-5.*$',
        displayName: 'gpt-5',
        routeMode: 'pattern',
        sourceRouteIds: [],
        enabled: true,
      },
    ];

    const visible = buildVisibleRouteList(
      routes,
      (pattern) => !pattern.includes('*') && !pattern.startsWith('re:'),
      (model, pattern) => pattern.startsWith('re:') && /^gpt-5.*$/.test(model),
    );

    expect(visible.map((route) => route.id)).toEqual([1, 2]);
  });
});
