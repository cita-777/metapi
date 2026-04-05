export type DesktopWindowOpenAction = 'allow' | 'deny';

export type DesktopWindowOpenDetails = {
  url: string;
};

export type DesktopWillNavigateEvent = {
  preventDefault: () => void;
};

export type DesktopWebContentsLike = {
  setWindowOpenHandler: (
    handler: (details: DesktopWindowOpenDetails) => { action: DesktopWindowOpenAction },
  ) => void;
  on: (
    event: 'will-navigate',
    listener: (event: DesktopWillNavigateEvent, url: string) => void,
  ) => void;
};

export type AttachDesktopNavigationGuardInput = {
  appUrl: string;
  openExternal: (url: string) => void;
  webContents: DesktopWebContentsLike;
};

export type CreateSafeOpenExternalInput = {
  openExternal: (url: string) => Promise<void>;
  onError: (url: string, error: unknown) => void;
};

export function resolveDesktopNavigationAction(
  targetUrl: string,
  appUrl: string,
): DesktopWindowOpenAction {
  let appLocation: URL;
  let targetLocation: URL;

  try {
    appLocation = new URL(appUrl);
    targetLocation = new URL(targetUrl, appLocation);
  } catch {
    return 'deny';
  }

  if (targetLocation.protocol === 'about:') {
    return 'allow';
  }

  return targetLocation.origin === appLocation.origin ? 'allow' : 'deny';
}

export function createSafeOpenExternal(
  input: CreateSafeOpenExternalInput,
): (url: string) => void {
  return (url: string) => {
    void input.openExternal(url).catch((error) => {
      input.onError(url, error);
    });
  };
}

export function attachDesktopNavigationGuard(
  input: AttachDesktopNavigationGuardInput,
): void {
  input.webContents.setWindowOpenHandler(({ url }) => {
    const action = resolveDesktopNavigationAction(url, input.appUrl);
    if (action === 'deny') {
      void input.openExternal(url);
    }
    return { action };
  });

  input.webContents.on('will-navigate', (event, url) => {
    if (resolveDesktopNavigationAction(url, input.appUrl) === 'allow') {
      return;
    }
    event.preventDefault();
    void input.openExternal(url);
  });
}
