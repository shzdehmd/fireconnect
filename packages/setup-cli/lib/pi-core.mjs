import { createHash } from "node:crypto";
import { chmod, mkdir, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import {
  DEFAULT_FIREPASS_MAIN_MODEL,
  DEFAULT_MAIN_MODEL,
  detectApiKeyType,
  normalizeModelId,
  readJsonIfExists,
  writeJson,
} from "./fireconnect-core.mjs";
import { readRawIfExists } from "./opencode-core.mjs";

export const PI_SETTINGS_RELATIVE_PATH = ".pi/agent/settings.json";
export const PI_MODELS_RELATIVE_PATH = ".pi/agent/models.json";
export const PI_DATA_RELATIVE_DIR = ".fireconnect/pi";
export const PI_API_KEY_ENV_REF = "$FIREWORKS_API_KEY";
const PI_PROVIDER = "fireworks";
const PI_MANAGED_BY = "fireconnect";

/** Fireworks routers FireConnect uses that Pi does not ship in its models.dev snapshot. */
const PI_FIREWORKS_ROUTER_ENTRIES = [
  { id: "accounts/fireworks/routers/glm-latest", name: "GLM Latest via Fireworks" },
  { id: "accounts/fireworks/routers/kimi-fast-latest", name: "Kimi Fast Latest via Fireworks" },
  { id: "accounts/fireworks/routers/kimi-k2p6-turbo", name: "Kimi K2.6 Turbo via Fireworks" },
  { id: "accounts/fireworks/routers/kimi-k2p7-code-fast", name: "Kimi K2.7 Code Fast via Fireworks" },
  { id: "accounts/fireworks/routers/kimi-latest", name: "Kimi Latest via Fireworks" },
];

function isFireconnectActive(settings) {
  return settings.defaultProvider === PI_PROVIDER
    && typeof settings.defaultModel === "string"
    && settings.defaultModel.startsWith("accounts/fireworks/");
}

function isFireconnectManagedAuth(auth) {
  return auth[PI_PROVIDER]?.managedBy === PI_MANAGED_BY;
}

export function piSettingsPath(home, settingsPath = "") {
  return settingsPath || path.join(home, PI_SETTINGS_RELATIVE_PATH);
}

export function piAuthPath(home, authPath = "", settingsPath = "") {
  if (authPath) {
    return authPath;
  }
  if (settingsPath) {
    return path.join(path.dirname(settingsPath), "auth.json");
  }
  return path.join(home, ".pi/agent/auth.json");
}

export function piModelsPath(home, settingsPath = "") {
  if (settingsPath) {
    return path.join(path.dirname(settingsPath), "models.json");
  }
  return path.join(home, PI_MODELS_RELATIVE_PATH);
}

function fireworksModelEntry(modelId) {
  const shortId = modelId.split("/").pop() ?? modelId;
  return {
    id: modelId,
    name: `${shortId} via Fireworks`,
    reasoning: true,
  };
}

function piModelsToRegister(resolvedModel) {
  const entries = [...PI_FIREWORKS_ROUTER_ENTRIES.map((entry) => ({
    ...entry,
    reasoning: true,
  }))];
  if (resolvedModel.startsWith("accounts/fireworks/")
    && !entries.some((entry) => entry.id === resolvedModel)) {
    entries.push(fireworksModelEntry(resolvedModel));
  }
  return entries;
}

export function mergePiFireworksRouterModels(config, resolvedModel) {
  const next = config && typeof config === "object"
    ? structuredClone(config)
    : { providers: {} };
  next.providers ??= {};
  const fireworks = { ...(next.providers[PI_PROVIDER] ?? {}) };
  const models = [...(fireworks.models ?? [])];
  for (const entry of piModelsToRegister(resolvedModel)) {
    const index = models.findIndex((model) => model.id === entry.id);
    if (index >= 0) {
      models[index] = { ...models[index], ...entry };
    } else {
      models.push(entry);
    }
  }
  fireworks.models = models;
  next.providers[PI_PROVIDER] = fireworks;
  return next;
}

export function piDataDir(home, dataDir = "") {
  return dataDir || path.join(home, PI_DATA_RELATIVE_DIR);
}

function backupPath(dataDir, filePath, label) {
  const key = createHash("sha256").update(path.resolve(filePath)).digest("hex").slice(0, 16);
  return path.join(dataDir, `${label}-backup.${key}.json`);
}

function statePath(dataDir) {
  return path.join(dataDir, "state.json");
}

async function writeState(dataDir, enabled, managedModelIds = []) {
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await writeJson(statePath(dataDir), { enabled, managedModelIds });
  await chmod(statePath(dataDir), 0o600);
}

export function resolvePiApiKeyValue(key) {
  return key === PI_API_KEY_ENV_REF || key === "${FIREWORKS_API_KEY}"
    ? (process.env.FIREWORKS_API_KEY ?? "")
    : key;
}

export function piAuthKeyMode(key) {
  if (!key) {
    return "missing";
  }
  return key === PI_API_KEY_ENV_REF || key === "${FIREWORKS_API_KEY}" ? "env-reference" : "literal";
}

export function piProviderStatus(settings) {
  const model = typeof settings.defaultModel === "string" ? settings.defaultModel : "";
  const fireworksModel = model.startsWith("accounts/fireworks/");
  if (settings.defaultProvider === PI_PROVIDER && fireworksModel) {
    return "fireworks";
  }
  if (settings.defaultProvider === PI_PROVIDER || fireworksModel) {
    return "custom";
  }
  return "default";
}

async function writePrivateBackup(dataDir, dest, filePath, snapshot) {
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await writeJson(dest, { filePath: path.resolve(filePath), snapshot });
  await chmod(dest, 0o600);
}

async function writeAuthFile(authPath, auth) {
  await mkdir(path.dirname(authPath), { recursive: true });
  await writeFile(authPath, `${JSON.stringify(auth, null, 2)}\n`, "utf8");
  await chmod(authPath, 0o600);
}

async function restoreSnapshot(filePath, snapshot) {
  if (snapshot.existed) {
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, snapshot.raw, "utf8");
    if (filePath.endsWith("auth.json")) {
      await chmod(filePath, 0o600);
    }
    return;
  }
  await unlink(filePath).catch((error) => {
    if (error.code !== "ENOENT") {
      throw error;
    }
  });
}

async function parseJsonFile(filePath, snapshot) {
  if (!snapshot.existed || !snapshot.raw.trim()) {
    return {};
  }
  try {
    return JSON.parse(snapshot.raw);
  } catch {
    throw new Error(`${filePath} is not valid JSON`);
  }
}

export async function enablePiFireworks({
  settingsPath,
  authPath,
  modelsPath,
  dataDir,
  apiKey,
  apiKeyFromFlag = false,
  modelId,
  keyType = "fireworks",
}) {
  if (!apiKey) {
    throw new Error("No Fireworks API key found. Pass --api-key or set FIREWORKS_API_KEY.");
  }

  const settingsSnapshot = await readRawIfExists(settingsPath);
  const authSnapshot = await readRawIfExists(authPath);
  const modelsSnapshot = await readRawIfExists(modelsPath);
  const settings = await parseJsonFile(settingsPath, settingsSnapshot);
  const auth = await parseJsonFile(authPath, authSnapshot);
  const modelsConfig = await parseJsonFile(modelsPath, modelsSnapshot);

  const resolvedKeyType = keyType === "fireworks"
    ? detectApiKeyType(resolvePiApiKeyValue(apiKey))
    : keyType;
  let effectiveModelId = modelId;
  if (resolvedKeyType === "firepass" && !modelId) {
    effectiveModelId = DEFAULT_FIREPASS_MAIN_MODEL;
  }
  const resolvedModel = normalizeModelId(
    effectiveModelId || DEFAULT_MAIN_MODEL,
  );

  const settingsBackup = backupPath(dataDir, settingsPath, "settings");
  const hasActiveBackup = (await readJsonIfExists(settingsBackup)).snapshot !== undefined;
  const hasFireworksModel = typeof settings.defaultModel === "string"
    && settings.defaultModel.startsWith("accounts/fireworks/");

  if (!hasActiveBackup) {
    await writePrivateBackup(dataDir, settingsBackup, settingsPath, settingsSnapshot);
    if (authSnapshot.existed) {
      await writePrivateBackup(dataDir, backupPath(dataDir, authPath, "auth"), authPath, authSnapshot);
    }
    await writePrivateBackup(dataDir, backupPath(dataDir, modelsPath, "models"), modelsPath, modelsSnapshot);
  } else if (settings.defaultProvider !== PI_PROVIDER && !hasFireworksModel) {
    await writePrivateBackup(dataDir, settingsBackup, settingsPath, settingsSnapshot);
    if (authSnapshot.existed) {
      await writePrivateBackup(dataDir, backupPath(dataDir, authPath, "auth"), authPath, authSnapshot);
    }
    await writePrivateBackup(dataDir, backupPath(dataDir, modelsPath, "models"), modelsPath, modelsSnapshot);
  }

  const apiKeyValue = apiKeyFromFlag ? apiKey : PI_API_KEY_ENV_REF;
  await writeJson(settingsPath, {
    ...settings,
    defaultProvider: PI_PROVIDER,
    defaultModel: resolvedModel,
  });
  await writeAuthFile(authPath, {
    ...auth,
    [PI_PROVIDER]: { type: "api_key", key: apiKeyValue, managedBy: PI_MANAGED_BY },
  });
  await writeJson(modelsPath, mergePiFireworksRouterModels(modelsConfig, resolvedModel));
  const managedModelIds = piModelsToRegister(resolvedModel).map((entry) => entry.id);
  await writeState(dataDir, true, managedModelIds);

  return {
    model: resolvedModel,
    apiKeyMode: piAuthKeyMode(apiKeyValue),
    keyType: resolvedKeyType,
  };
}

async function restoreBackedUpFile(filePath, backupPath, label) {
  const backup = await readJsonIfExists(backupPath);
  if (backup.snapshot !== undefined
    && backup.filePath !== undefined
    && backup.filePath !== path.resolve(filePath)) {
    throw new Error(`Backup was taken for ${backup.filePath}, not ${filePath}; refusing to restore ${label}.`);
  }
  if (backup.snapshot !== undefined) {
    if (label === "auth" && !backup.snapshot.existed) {
      await unlink(backupPath).catch(() => {});
      return false;
    }
    await restoreSnapshot(filePath, backup.snapshot);
    await unlink(backupPath).catch(() => {});
    return true;
  }
  return false;
}

async function stripManagedSettings(settingsPath) {
  if (!(await readRawIfExists(settingsPath)).existed) {
    return false;
  }
  const settings = await readJsonIfExists(settingsPath);
  const next = { ...settings };
  let changed = false;
  if (next.defaultProvider === PI_PROVIDER) {
    delete next.defaultProvider;
    changed = true;
  }
  if (typeof next.defaultModel === "string" && next.defaultModel.startsWith("accounts/fireworks/")) {
    delete next.defaultModel;
    changed = true;
  }
  if (changed) {
    await writeJson(settingsPath, next);
  }
  return changed;
}

function managedModelIdsFromState(state) {
  if (Array.isArray(state.managedModelIds) && state.managedModelIds.length > 0) {
    return state.managedModelIds;
  }
  return PI_FIREWORKS_ROUTER_ENTRIES.map((entry) => entry.id);
}

async function stripManagedModels(modelsPath, managedModelIds) {
  if (!(await readRawIfExists(modelsPath)).existed) {
    return false;
  }
  const config = await readJsonIfExists(modelsPath);
  const fireworks = config.providers?.[PI_PROVIDER];
  if (!fireworks || !Array.isArray(fireworks.models)) {
    return false;
  }

  const managedIds = new Set(managedModelIds);
  const remaining = fireworks.models.filter((model) => !managedIds.has(model.id));
  if (remaining.length === fireworks.models.length) {
    return false;
  }

  const next = { ...config, providers: { ...config.providers } };
  if (remaining.length === 0) {
    delete next.providers[PI_PROVIDER];
    if (Object.keys(next.providers).length === 0) {
      await unlink(modelsPath).catch((error) => {
        if (error.code !== "ENOENT") {
          throw error;
        }
      });
      return true;
    }
  } else {
    next.providers[PI_PROVIDER] = { ...fireworks, models: remaining };
  }
  await writeJson(modelsPath, next);
  return true;
}

async function stripManagedAuth(authPath) {
  if (!(await readRawIfExists(authPath)).existed) {
    return false;
  }
  const auth = await readJsonIfExists(authPath);
  if (!isFireconnectManagedAuth(auth)) {
    return false;
  }
  const next = { ...auth };
  delete next[PI_PROVIDER];
  if (Object.keys(next).length === 0) {
    await unlink(authPath).catch((error) => {
      if (error.code !== "ENOENT") {
        throw error;
      }
    });
  } else {
    await writeAuthFile(authPath, next);
  }
  return true;
}

export async function disablePiFireworks({ settingsPath, authPath, modelsPath, dataDir }) {
  const state = await readJsonIfExists(statePath(dataDir));
  const wasEnabled = state.enabled === true;
  const managedModelIds = managedModelIdsFromState(state);
  const settingsBackup = backupPath(dataDir, settingsPath, "settings");
  const hasBackup = (await readJsonIfExists(settingsBackup)).snapshot !== undefined;

  if (!wasEnabled && !hasBackup) {
    const auth = await readJsonIfExists(authPath);
    const settings = await readJsonIfExists(settingsPath);
    const hasFireconnectState = (await readRawIfExists(statePath(dataDir))).existed;
    if (!isFireconnectManagedAuth(auth)) {
      if (!hasFireconnectState || !isFireconnectActive(settings)) {
        return { changed: false };
      }
    }
    let changed = false;
    changed = (await stripManagedSettings(settingsPath)) || changed;
    if (isFireconnectManagedAuth(auth)) {
      changed = (await stripManagedAuth(authPath)) || changed;
    }
    changed = (await stripManagedModels(modelsPath, managedModelIds)) || changed;
    if (!changed) {
      return { changed: false };
    }
    await writeState(dataDir, false, []);
    return { changed: true };
  }

  const restoredSettings = await restoreBackedUpFile(settingsPath, settingsBackup, "settings");
  let changed = restoredSettings;
  if (!restoredSettings && wasEnabled) {
    changed = (await stripManagedSettings(settingsPath)) || changed;
  }

  const restoredAuth = await restoreBackedUpFile(
    authPath,
    backupPath(dataDir, authPath, "auth"),
    "auth",
  );
  if (restoredAuth) {
    changed = true;
  } else {
    changed = (await stripManagedAuth(authPath)) || changed;
  }

  const restoredModels = await restoreBackedUpFile(
    modelsPath,
    backupPath(dataDir, modelsPath, "models"),
    "models",
  );
  if (restoredModels) {
    changed = true;
  } else {
    changed = (await stripManagedModels(modelsPath, managedModelIds)) || changed;
  }

  await writeState(dataDir, false, []);
  return { changed };
}
