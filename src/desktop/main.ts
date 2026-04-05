import {
  app,
  BrowserWindow,
  Menu,
  Tray,
  dialog,
  nativeImage,
  shell,
} from 'electron';
import log from 'electron-log';
import electronUpdater from 'electron-updater';
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  buildDesktopServerEnv,
  createDesktopHealthUrl,
  createDesktopServerUrl,
  isFatalServerExit,
  resolveDesktopServerPort,
  resolveDesktopServerWorkingDir,
  waitForServerReady,
} from './runtime.js';
import { getDesktopRuntimeIconPath, getDesktopTrayIconPath } from './iconAssets.js';
import { attachDesktopNavigationGuard, createSafeOpenExternal } from './navigationGuard.js';

const { autoUpdater } = electronUpdater;

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let serverProcess: ChildProcess | null = null;
let serverUrl = '';
let isQuitting = false;
let isRestartingBackend = false;

log.initialize();

function getUserDataDir() {
  return join(app.getPath('userData'), 'data');
}

function getLogsDir() {
  return join(app.getPath('userData'), 'logs');
}

function ensureDesktopDirs() {
  mkdirSync(getUserDataDir(), { recursive: true });
  mkdirSync(getLogsDir(), { recursive: true });
}

function getServerEntryPath() {
  return join(app.getAppPath(), 'dist', 'server', 'index.js');
}

function getTrayIconPath() {
  return getDesktopTrayIconPath(app.getAppPath(), process.platform);
}

function getWindowIconPath() {
  return getTrayIconPath();
}

function resolveFrontendUrl() {
  const devUrl = (process.env.METAPI_DESKTOP_DEV_SERVER_URL || '').trim();
  if (devUrl) return devUrl;
  return serverUrl;
}

function resolveExternalServerUrl() {
  return (process.env.METAPI_DESKTOP_EXTERNAL_SERVER_URL || '').trim();
}

function showMainWindow() {
  if (!mainWindow) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function buildTrayMenu() {
  return Menu.buildFromTemplate([
    {
      label: 'Open Metapi',
      click: () => showMainWindow(),
    },
    {
      label: 'Restart Backend',
      click: () => {
        void restartBackend();
      },
    },
    {
      label: 'Launch at Login',
      type: 'checkbox',
      checked: app.getLoginItemSettings().openAtLogin,
      click: (menuItem) => {
        app.setLoginItemSettings({ openAtLogin: menuItem.checked });
        tray?.setContextMenu(buildTrayMenu());
      },
    },
    {
      label: 'Check for Updates',
      click: () => {
        void checkForUpdates(true);
      },
    },
    {
      label: 'Open Logs Folder',
      click: () => {
        void shell.openPath(getLogsDir());
      },
    },
    {
      label: 'Quit',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);
}

function setupTray() {
  if (tray) return;
  let trayImage = nativeImage.createFromPath(getTrayIconPath());
  if (process.platform === 'darwin' && !trayImage.isEmpty()) {
    trayImage = trayImage.resize({
      width: 18,
      height: 18,
      quality: 'best',
    });
    trayImage.setTemplateImage(true);
  }
  tray = new Tray(trayImage);
  tray.setToolTip('Metapi');
  tray.setContextMenu(buildTrayMenu());
  tray.on('double-click', () => showMainWindow());
}

async function createMainWindow() {
  if (mainWindow) return mainWindow;
  const frontendUrl = resolveFrontendUrl();

  mainWindow = new BrowserWindow({
    width: 1480,
    height: 960,
    minWidth: 1180,
    minHeight: 760,
    show: false,
    icon: existsSync(getWindowIconPath()) ? getWindowIconPath() : undefined,
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  attachDesktopNavigationGuard({
    appUrl: frontendUrl,
    openExternal: createSafeOpenExternal({
      openExternal: (url) => shell.openExternal(url),
      onError: (url, error) => {
        log.error('Failed to open external URL', { url, error });
      },
    }),
    webContents: mainWindow.webContents,
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  await mainWindow.loadURL(frontendUrl);
  return mainWindow;
}

function attachServerLogs(processHandle: ChildProcess) {
  processHandle.stdout?.on('data', (chunk) => {
    log.info(`[server] ${String(chunk).trimEnd()}`);
  });
  processHandle.stderr?.on('data', (chunk) => {
    log.error(`[server] ${String(chunk).trimEnd()}`);
  });
}

async function waitForManagedServerReady(url: string) {
  await waitForServerReady({
    url,
    timeoutMs: 45_000,
    intervalMs: 250,
  });
}

async function startManagedBackend() {
  ensureDesktopDirs();
  const serverEntryPath = getServerEntryPath();
  const port = resolveDesktopServerPort(process.env);
  serverUrl = createDesktopServerUrl(port);

  const env = buildDesktopServerEnv({
    inheritedEnv: process.env,
    userDataDir: getUserDataDir(),
    logsDir: getLogsDir(),
    port,
  });

  const child = spawn(process.execPath, [serverEntryPath], {
    cwd: resolveDesktopServerWorkingDir({
      appPath: app.getAppPath(),
      resourcesPath: process.resourcesPath,
      isPackaged: app.isPackaged,
    }),
    env: {
      ...env,
      ELECTRON_RUN_AS_NODE: '1',
      NODE_ENV: app.isPackaged ? 'production' : 'development',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  serverProcess = child;

  attachServerLogs(child);

  child.once('exit', (code, signal) => {
    const fatal = isFatalServerExit({ code, signal });
    serverProcess = null;
    if (!fatal || isQuitting || isRestartingBackend) return;
    void handleServerCrash(code);
  });

  await waitForManagedServerReady(createDesktopHealthUrl(port));
}

async function connectToExternalBackend() {
  const externalServerUrl = resolveExternalServerUrl();
  serverUrl = externalServerUrl;
  await waitForServerReady({
    url: `${externalServerUrl}/api/desktop/health`,
    timeoutMs: 45_000,
    intervalMs: 250,
  });
}

async function stopManagedBackend() {
  if (!serverProcess) return;

  await new Promise<void>((resolve) => {
    const current = serverProcess;
    if (!current) {
      resolve();
      return;
    }

    const timeout = setTimeout(() => {
      current.kill('SIGKILL');
    }, 10_000);

    current.once('exit', () => {
      clearTimeout(timeout);
      resolve();
    });

    current.kill();
  });

  serverProcess = null;
}

async function handleServerCrash(code: number | null) {
  mainWindow?.hide();
  const result = await dialog.showMessageBox({
    type: 'error',
    title: 'Metapi backend stopped',
    message: `The local Metapi backend exited unexpectedly${typeof code === 'number' ? ` (code ${code})` : ''}.`,
    detail: 'You can restart the backend now or quit the desktop app.',
    buttons: ['Restart Backend', 'Quit'],
    defaultId: 0,
    cancelId: 1,
  });

  if (result.response === 0) {
    await restartBackend();
    return;
  }

  isQuitting = true;
  app.quit();
}

async function restartBackend() {
  if (isRestartingBackend) return;
  isRestartingBackend = true;
  try {
    await stopManagedBackend();
    if (resolveExternalServerUrl()) {
      await connectToExternalBackend();
    } else {
      await startManagedBackend();
    }
    if (mainWindow) {
      await mainWindow.loadURL(resolveFrontendUrl());
      showMainWindow();
    }
  } catch (error) {
    log.error('Failed to restart backend', error);
    await dialog.showMessageBox({
      type: 'error',
      title: 'Restart failed',
      message: 'Metapi could not restart the local backend.',
      detail: error instanceof Error ? error.message : String(error),
    });
  } finally {
    isRestartingBackend = false;
  }
}

async function checkForUpdates(isManual: boolean) {
  if (!app.isPackaged) {
    if (isManual) {
      await dialog.showMessageBox({
        type: 'info',
        title: 'Updates unavailable',
        message: 'Auto-update is only available for packaged desktop builds.',
      });
    }
    return;
  }

  try {
    await autoUpdater.checkForUpdates();
  } catch (error) {
    log.error('Failed to check for updates', error);
    if (isManual) {
      await dialog.showMessageBox({
        type: 'error',
        title: 'Update check failed',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
}

function setupAutoUpdater() {
  if (!app.isPackaged) return;

  autoUpdater.autoDownload = false;
  autoUpdater.logger = log;

  autoUpdater.on('update-available', async (info) => {
    const result = await dialog.showMessageBox({
      type: 'info',
      title: 'Update available',
      message: `Metapi ${info.version} is available.`,
      detail: 'Download and install it after the current session?',
      buttons: ['Download', 'Later'],
      defaultId: 0,
      cancelId: 1,
    });

    if (result.response === 0) {
      await autoUpdater.downloadUpdate();
    }
  });

  autoUpdater.on('update-not-available', async () => {
    log.info('No desktop updates available');
  });

  autoUpdater.on('update-downloaded', async () => {
    const result = await dialog.showMessageBox({
      type: 'info',
      title: 'Update ready',
      message: 'The new Metapi desktop update is ready to install.',
      buttons: ['Install and Restart', 'Later'],
      defaultId: 0,
      cancelId: 1,
    });

    if (result.response === 0) {
      isQuitting = true;
      autoUpdater.quitAndInstall();
    }
  });

  autoUpdater.on('error', (error) => {
    log.error('Auto-update error', error);
  });

  void checkForUpdates(false);
}

async function bootDesktopApp() {
  if (resolveExternalServerUrl()) {
    await connectToExternalBackend();
  } else {
    await startManagedBackend();
  }

  setupTray();
  await createMainWindow();
  setupAutoUpdater();
  app.setLoginItemSettings({ openAtLogin: app.getLoginItemSettings().openAtLogin });
}

const hasSingleInstanceLock = app.requestSingleInstanceLock();

if (!hasSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    showMainWindow();
  });

  app.whenReady()
    .then(async () => {
      try {
        await bootDesktopApp();
      } catch (error) {
        log.error('Failed to boot Metapi desktop', error);
        const result = await dialog.showMessageBox({
          type: 'error',
          title: 'Metapi failed to start',
          message: 'The desktop shell could not start the local Metapi service.',
          detail: error instanceof Error ? error.message : String(error),
          buttons: ['Retry', 'Quit'],
          defaultId: 0,
          cancelId: 1,
        });

        if (result.response === 0) {
          await bootDesktopApp();
          return;
        }

        isQuitting = true;
        app.quit();
      }
    })
    .catch((error) => {
      log.error('Unhandled startup error', error);
      isQuitting = true;
      app.quit();
    });
}

app.on('activate', () => {
  if (!mainWindow) {
    void createMainWindow();
    return;
  }
  showMainWindow();
});

app.on('before-quit', () => {
  isQuitting = true;
});

app.on('will-quit', () => {
  tray?.destroy();
  tray = null;
  void stopManagedBackend();
});

app.on('window-all-closed', () => {
  // Keep the tray resident app alive until the user explicitly quits.
});
