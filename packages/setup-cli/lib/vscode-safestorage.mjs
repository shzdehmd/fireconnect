import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { existsSync } from "node:fs";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { readFirstItemTableValueByKeyPrefix } from "./vscdb-sqlite.mjs";

/**
 * Electron `safeStorage`-compatible secret encryption.
 *
 * VS Code Chat's BYOK secrets (the `customendpoint` `apiKey`) are NOT stored as
 * a per-secret OS keychain entry. `LanguageModelsService` resolves the
 * `${input:chat.lm.secret.<id>}` reference via `ISecretStorageService.get(<id>)`,
 * which reads an **encrypted blob from the application-scoped `state.vscdb`**
 * (`ItemTable`, key `secret://<id>`) and decrypts it with Electron `safeStorage`
 * (see VS Code's `BaseSecretStorageService` + `EncryptionMainService`).
 *
 * The value stored in `state.vscdb` is exactly
 * `JSON.stringify(safeStorage.encryptString(plaintext))`, i.e. the JSON form of a
 * Node Buffer — `{"type":"Buffer","data":[...]}` — whose bytes are the platform
 * `safeStorage` ciphertext. This module reproduces that ciphertext so the harness
 * can write a key VS Code can actually read.
 *
 * Platform schemes (matching Chromium's OSCrypt, which Electron `safeStorage`
 * wraps):
 * - macOS:   `v10` + AES-128-CBC. Key = PBKDF2-HMAC-SHA1(masterPw, "saltysalt",
 *            1003, 16). IV = 16×0x20. The master password is a random value in
 *            the login keychain under service "<AppName> Safe Storage".
 * - Windows: `v10` + AES-256-GCM. Key = 32 random bytes, DPAPI-encrypted and
 *            stored in the "Local State" JSON file under
 *            `os_crypt.encrypted_key`. Ciphertext = v10 + nonce(12) +
 *            AES-256-GCM(secret, nonce, key) + tag(16). Legacy secrets used raw
 *            DPAPI without a prefix; decryptSecret falls back to that.
 * - Linux:   `v10`/`v11` + AES-128-CBC. Key = PBKDF2-HMAC-SHA1(masterPw,
 *            "saltysalt", iterations, 16). IV = 16×0x20. The master password
 *            comes from libsecret (keyring) or the hardcoded "peanuts" string
 *            (basic_text backend). Iteration count and version prefix vary by
 *            Chromium generation (1+1iter modern, 1003+1iter older).
 *
 * Test seam: when FIRECONNECT_VSCODE_SECRET_PLAINTEXT is set, encrypt/decrypt are
 * the identity (the raw key is stored verbatim). VS Code does NOT read such a
 * value — this is only for exercising the harness's logic headlessly/in CI.
 */

const SALT = "saltysalt";
const ITERATIONS = 1003;
const KEY_LEN = 16;
const IV = Buffer.alloc(16, 0x20);
const LINUX_BASIC_PASSWORD = "peanuts";

/** @returns {boolean} whether the plaintext test seam is active. */
function plaintextMode() {
  return Boolean(process.env.FIRECONNECT_VSCODE_SECRET_PLAINTEXT);
}

/**
 * Electron app name for the variant. Stable VS Code's keychain item is
 * "Code Safe Storage"; Insiders is "Code - Insiders Safe Storage".
 * @param {"stable" | "insiders"} [variant]
 * @returns {string}
 */
function appNameFor(variant) {
  return variant === "insiders" ? "Code - Insiders" : "Code";
}

/* -------------------------------------------------------------------------- */
/* OSCrypt AES (macOS + Linux)                                                 */
/* -------------------------------------------------------------------------- */

/** Derive the AES-128 key from a master password (Chromium OSCrypt KDF). */
function deriveKey(masterPassword, iterations = ITERATIONS) {
  return crypto.pbkdf2Sync(masterPassword, SALT, iterations, KEY_LEN, "sha1");
}

/**
 * Chromium OSCrypt AES encryption (macOS `v10`, Linux `v10`/`v11`). Exported for
 * unit tests; production callers go through {@link encryptSecret}.
 * @param {string} plaintext @param {string} masterPassword @param {string} version
 * @param {number} [iterations]
 */
export function aesEncrypt(plaintext, masterPassword, version, iterations = ITERATIONS) {
  const key = deriveKey(masterPassword, iterations);
  const cipher = crypto.createCipheriv("aes-128-cbc", key, IV);
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([Buffer.from(version, "latin1"), body]);
}

/**
 * Chromium OSCrypt AES decryption (inverse of {@link aesEncrypt}). Exported for
 * unit tests; production callers go through {@link decryptSecret}.
 * @param {Buffer} blob @param {string} masterPassword @param {number} [iterations]
 */
export function aesDecrypt(blob, masterPassword, iterations = ITERATIONS) {
  const key = deriveKey(masterPassword, iterations);
  const body = blob.subarray(3); // strip the 3-byte "vNN" version prefix
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, IV);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}

/* -------------------------------------------------------------------------- */
/* macOS — master password from the login keychain                            */
/* -------------------------------------------------------------------------- */

/**
 * Read the Safe Storage master password from the macOS login keychain.
 * @param {"stable" | "insiders"} [variant]
 * @returns {string} the password, or "" if not found.
 */
function macReadMasterPassword(variant) {
  const service = `${appNameFor(variant)} Safe Storage`;
  const r = spawnSync("security", ["find-generic-password", "-s", service, "-w"], {
    encoding: "utf8",
  });
  if (r.status !== 0) {
    return "";
  }
  return (r.stdout || "").replace(/\n$/, "");
}

/* -------------------------------------------------------------------------- */
/* Linux — master password from libsecret, else "peanuts" (basic backend)      */
/* -------------------------------------------------------------------------- */

/**
 * Try to read the Safe Storage master password from the Linux keyring. Chromium
 * stores it under a libsecret item labelled "<App> Safe Storage". We probe the
 * common attribute schemes; on failure callers fall back to the basic backend.
 * @param {"stable" | "insiders"} [variant]
 * @returns {string} the password, or "" when no keyring entry is found.
 */
function linuxReadMasterPassword(variant) {
  const app = appNameFor(variant);
  const attempts = [
    ["application", app],
    ["application", app.toLowerCase()],
    ["application", "chromium"],
  ];
  for (const attrs of attempts) {
    const r = spawnSync("secret-tool", ["lookup", ...attrs], { encoding: "utf8" });
    if (r.status === 0 && (r.stdout || "").length > 0) {
      return r.stdout.replace(/\n$/, "");
    }
  }
  return "";
}

/* -------------------------------------------------------------------------- */
/* Windows — DPAPI + AES-256-GCM (modern Chromium OSCrypt)                     */
/*                                                                            */
/* Modern Chromium on Windows does NOT use raw DPAPI on each secret. Instead:  */
/*  1. A random 32-byte AES-256-GCM key is generated on first launch.          */
/*  2. The key is DPAPI-encrypted, prefixed with "DPAPI", base64-encoded, and  */
/*     stored in the "Local State" JSON file under os_crypt.encrypted_key.     */
/*  3. Each secret is encrypted with AES-256-GCM using that key.               */
/*  4. The ciphertext format is: "v10" + nonce(12) + AES-256-GCM ciphertext.   */
/*                                                                            */
/* Legacy (older Chromium) used raw DPAPI on the whole plaintext with no       */
/* prefix. decryptSecret tries v10+GCM first, then falls back to raw DPAPI.    */
/* -------------------------------------------------------------------------- */

/** AES-256-GCM key size in bytes. */
const WIN_GCM_KEY_SIZE = 32;
/** AES-256-GCM nonce size in bytes (Chromium uses 96-bit nonces). */
const WIN_GCM_NONCE_SIZE = 12;
/** Provider prefix Chromium prepends to AES-256-GCM ciphertext on Windows. */
const WIN_V10_PREFIX = Buffer.from("v10", "latin1");
/** Prefix on the DPAPI-encrypted key in Local State (not on the secret itself). */
const WIN_DPAPI_KEY_PREFIX = Buffer.from("DPAPI", "latin1");

/**
 * Run a PowerShell snippet that prints a single base64 line, or "" on failure.
 * @param {string} script
 * @returns {string}
 */
function runPowerShell(script) {
  const r = spawnSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8",
  });
  if (r.status !== 0) {
    return "";
  }
  return (r.stdout || "").replace(/\r?\n/g, "").trim();
}

/** @param {string} plaintext @returns {Buffer} DPAPI-protected bytes (empty on failure). */
function windowsProtect(plaintext) {
  const b64 = Buffer.from(plaintext, "utf8").toString("base64");
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    `$bytes=[Convert]::FromBase64String('${b64}')`,
    "$enc=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[Convert]::ToBase64String($enc)",
  ].join(";");
  const out = runPowerShell(script);
  return out ? Buffer.from(out, "base64") : Buffer.alloc(0);
}

/** @param {Buffer} blob @returns {string} the decrypted plaintext (empty on failure). */
function windowsUnprotect(blob) {
  const b64 = blob.toString("base64");
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    `$bytes=[Convert]::FromBase64String('${b64}')`,
    "$dec=[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[Convert]::ToBase64String($dec)",
  ].join(";");
  const out = runPowerShell(script);
  return out ? Buffer.from(out, "base64").toString("utf8") : "";
}

/**
 * DPAPI-encrypt a raw Buffer and return the protected bytes as a Buffer.
 * Unlike {@link windowsProtect} (which takes a string), this preserves binary
 * data integrity — critical for the 32-byte AES key.
 * @param {Buffer} data
 * @returns {Buffer}
 */
function windowsProtectBuffer(data) {
  const b64 = data.toString("base64");
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    `$bytes=[Convert]::FromBase64String('${b64}')`,
    "$enc=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[Convert]::ToBase64String($enc)",
  ].join(";");
  const out = runPowerShell(script);
  return out ? Buffer.from(out, "base64") : Buffer.alloc(0);
}

/**
 * DPAPI-decrypt a raw Buffer and return the plaintext as a Buffer.
 * Unlike {@link windowsUnprotect} (which returns a UTF-8 string), this
 * preserves binary data — critical for the 32-byte AES key.
 * @param {Buffer} blob
 * @returns {Buffer} decrypted bytes (empty on failure)
 */
function windowsUnprotectBuffer(blob) {
  const b64 = blob.toString("base64");
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    `$bytes=[Convert]::FromBase64String('${b64}')`,
    "$dec=[System.Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[Convert]::ToBase64String($dec)",
  ].join(";");
  const out = runPowerShell(script);
  return out ? Buffer.from(out, "base64") : Buffer.alloc(0);
}

/**
 * Resolve the path to VS Code's "Local State" file from a `state.vscdb` path.
 * `state.vscdb` is at `<userData>/User/globalStorage/state.vscdb`, and
 * `Local State` is at `<userData>/Local State`.
 * @param {string} stateDbPath
 * @returns {string}
 */
function localStatePathFromStateDb(stateDbPath) {
  // <userData>/User/globalStorage/state.vscdb -> <userData>/Local State
  return path.join(path.dirname(stateDbPath), "..", "..", "Local State");
}

/**
 * Read, DPAPI-decrypt, and return the 32-byte AES-256-GCM key from VS Code's
 * "Local State" file. If the key doesn't exist yet, generate a new one,
 * DPAPI-encrypt it, and write it back so VS Code can use it on next launch.
 * @param {string} localStatePath
 * @returns {Promise<Buffer | null>} 32-byte key, or null on failure
 */
async function windowsGetOrCreateAesKey(localStatePath) {
  let localState = {};
  if (existsSync(localStatePath)) {
    try {
      localState = JSON.parse(await readFile(localStatePath, "utf8"));
    } catch {
      localState = {};
    }
  }

  const stored = localState?.os_crypt?.encrypted_key;
  if (typeof stored === "string" && stored.length > 0) {
    const decoded = Buffer.from(stored, "base64");
    if (decoded.length > WIN_DPAPI_KEY_PREFIX.length &&
        decoded.subarray(0, WIN_DPAPI_KEY_PREFIX.length).equals(WIN_DPAPI_KEY_PREFIX)) {
      const encryptedKey = decoded.subarray(WIN_DPAPI_KEY_PREFIX.length);
      const decrypted = windowsUnprotectBuffer(encryptedKey);
      if (decrypted.length === WIN_GCM_KEY_SIZE) {
        return decrypted;
      }
    }
  }

  // Key doesn't exist or is invalid — generate a new one.
  const newKey = crypto.randomBytes(WIN_GCM_KEY_SIZE);
  const protectedKey = windowsProtectBuffer(newKey);
  if (protectedKey.length === 0) {
    return null;
  }
  const prefixed = Buffer.concat([WIN_DPAPI_KEY_PREFIX, protectedKey]);
  localState.os_crypt = localState.os_crypt || {};
  localState.os_crypt.encrypted_key = prefixed.toString("base64");

  await mkdir(path.dirname(localStatePath), { recursive: true });
  await writeFile(localStatePath, JSON.stringify(localState, null, "\t"), "utf8");

  return newKey;
}

/**
 * Encrypt a plaintext string using the v10 + AES-256-GCM format that modern
 * Chromium's OSCrypt uses on Windows.
 * @param {string} plaintext
 * @param {Buffer} aesKey 32-byte AES-256 key
 * @returns {Buffer} v10 + nonce(12) + AES-256-GCM ciphertext + tag
 */
function windowsGcmEncrypt(plaintext, aesKey) {
  const nonce = crypto.randomBytes(WIN_GCM_NONCE_SIZE);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  // Chromium's format: nonce at the front, then ciphertext+tag
  return Buffer.concat([WIN_V10_PREFIX, nonce, ciphertext, tag]);
}

/**
 * Decrypt a v10-prefixed AES-256-GCM ciphertext.
 * @param {Buffer} blob the full blob including the "v10" prefix
 * @param {Buffer} aesKey 32-byte AES-256 key
 * @returns {string} plaintext, or "" on failure
 */
function windowsGcmDecrypt(blob, aesKey) {
  const body = blob.subarray(WIN_V10_PREFIX.length); // strip "v10"
  if (body.length < WIN_GCM_NONCE_SIZE + 16) {
    return ""; // too short: need at least nonce + tag
  }
  const nonce = body.subarray(0, WIN_GCM_NONCE_SIZE);
  const ciphertext = body.subarray(WIN_GCM_NONCE_SIZE, body.length - 16);
  const tag = body.subarray(body.length - 16);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch {
    return "";
  }
}

/* -------------------------------------------------------------------------- */
/* Linux — OSCrypt parameter detection                                          */
/* -------------------------------------------------------------------------- */

/**
 * On Linux, Chromium's OSCrypt has two backends and two KDF generations, giving
 * four possible parameter sets:
 *
 * | password | iterations | prefix | Chromium generation |
 * |----------|-----------|--------|---------------------|
 * | keyring  | 1         | v11    | modern (Electron ~32+) |
 * | peanuts  | 1         | v11    | modern basic_text |
 * | keyring  | 1003      | v10    | older (Electron <32) |
 * | peanuts  | 1003      | v11    | older basic_text |
 *
 * The prefix alone does NOT tell us which password or iteration count to use —
 * modern Chromium uses v11 with the keyring password (libsecret backend), while
 * older Chromium used v10 with the keyring. Similarly, "peanuts" (basic_text)
 * can appear with v11 in both generations but with different iteration counts.
 *
 * This function probes an existing `secret://` entry in `state.vscdb` and tries
 * every combination until one successfully decrypts, returning the winning
 * parameters so `encryptSecret` can match them exactly.
 *
 * @typedef {{ password: string, iterations: number, version: string }} LinuxOscryptParams
 * @param {string} [stateDbPath]
 * @param {string} [keyringPw] pre-fetched keyring password (avoids redundant lookup)
 * @returns {Promise<LinuxOscryptParams | null>}
 */
async function detectLinuxOscryptParams(stateDbPath, keyringPw) {
  if (!stateDbPath) {
    return null;
  }
  const stored = await readFirstItemTableValueByKeyPrefix(stateDbPath, "secret://");
  if (!stored) {
    return null;
  }
  let blob;
  try {
    const parsed = JSON.parse(stored);
    if (!parsed || !Array.isArray(parsed.data) || parsed.data.length < 3) {
      return null;
    }
    blob = Buffer.from(parsed.data);
  } catch {
    return null;
  }

  const version = blob.subarray(0, 3).toString("latin1");
  // Build candidate parameter sets, most likely first.
  const candidates = [];
  if (keyringPw) {
    candidates.push({ password: keyringPw, iterations: 1, version: "v11" });
    candidates.push({ password: keyringPw, iterations: 1003, version: "v10" });
    candidates.push({ password: keyringPw, iterations: 1003, version: "v11" });
    candidates.push({ password: keyringPw, iterations: 1, version: "v10" });
  }
  candidates.push({ password: LINUX_BASIC_PASSWORD, iterations: 1, version: "v11" });
  candidates.push({ password: LINUX_BASIC_PASSWORD, iterations: 1003, version: "v11" });

  for (const c of candidates) {
    if (c.version !== version) {
      continue;
    }
    try {
      aesDecrypt(blob, c.password, c.iterations);
      return c;
    } catch {
      // wrong combination — try next
    }
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

/**
 * Encrypt a secret into the exact string VS Code stores in `state.vscdb`
 * (`JSON.stringify(safeStorage.encryptString(value))`).
 *
 * On Linux, the ciphertext version prefix (`v10` for keyring, `v11` for
 * basic_text) must match the backend VS Code actually uses, or VS Code won't be
 * able to decrypt the value. When `stateDbPath` is provided, the function
 * probes existing `secret://` entries in `state.vscdb` to detect the backend
 * VS Code is using. When no existing secrets are found, it falls back to `v11`
 * (basic_text / "peanuts"), which VS Code can always decrypt regardless of the
 * active backend.
 * @param {string} plaintext
 * @param {{ variant?: "stable" | "insiders", stateDbPath?: string }} [opts]
 * @returns {Promise<string>}
 */
export async function encryptSecret(plaintext, { variant, stateDbPath } = {}) {
  if (plaintextMode()) {
    return plaintext;
  }
  const platform = os.platform();
  if (platform === "darwin") {
    const pw = macReadMasterPassword(variant);
    if (!pw) {
      throw new Error(secretEncryptionUnavailableMessage(variant));
    }
    return JSON.stringify(aesEncrypt(plaintext, pw, "v10"));
  }
  if (platform === "win32") {
    // Modern Chromium uses v10 + AES-256-GCM with a DPAPI-protected key stored
    // in the "Local State" file. Raw DPAPI (the old approach) produces bytes
    // with no v10 prefix that VS Code's OSCrypt can't decrypt.
    const localStatePath = stateDbPath
      ? localStatePathFromStateDb(stateDbPath)
      : path.join(process.env.APPDATA || "", "Code", "Local State");
    const aesKey = await windowsGetOrCreateAesKey(localStatePath);
    if (!aesKey) {
      throw new Error(secretEncryptionUnavailableMessage(variant));
    }
    return JSON.stringify(windowsGcmEncrypt(plaintext, aesKey));
  }
  // linux / others — detect the exact OSCrypt parameters VS Code uses by
  // probing an existing secret in state.vscdb. Modern Chromium (Electron ~32+)
  // uses 1 PBKDF2 iteration and v11 prefix even with the keyring password,
  // while older Chromium used 1003 iterations and v10 for keyring. Matching the
  // wrong combination produces ciphertext VS Code can't decrypt.
  const keyringPw = linuxReadMasterPassword(variant);
  const detected = await detectLinuxOscryptParams(stateDbPath, keyringPw);
  if (detected) {
    return JSON.stringify(aesEncrypt(plaintext, detected.password, detected.version, detected.iterations));
  }
  // No existing secrets to probe — use modern defaults (1 iteration, v11).
  // Prefer the keyring password when available; fall back to "peanuts".
  if (keyringPw) {
    return JSON.stringify(aesEncrypt(plaintext, keyringPw, "v11", 1));
  }
  return JSON.stringify(aesEncrypt(plaintext, LINUX_BASIC_PASSWORD, "v11", 1));
}

/**
 * Decrypt a value read from `state.vscdb` (the JSON form of the safeStorage
 * ciphertext) back to plaintext. Returns "" when it can't be decrypted.
 * @param {string} stored
 * @param {{ variant?: "stable" | "insiders", stateDbPath?: string }} [opts]
 * @returns {Promise<string>}
 */
export async function decryptSecret(stored, { variant, stateDbPath } = {}) {
  if (stored === "" || stored == null) {
    return "";
  }
  if (plaintextMode()) {
    return stored;
  }
  let blob;
  try {
    const parsed = JSON.parse(stored);
    if (!parsed || !Array.isArray(parsed.data)) {
      return "";
    }
    blob = Buffer.from(parsed.data);
  } catch {
    return "";
  }
  try {
    const platform = os.platform();
    if (platform === "win32") {
      // Modern Chromium: v10 prefix + AES-256-GCM
      if (blob.length > WIN_V10_PREFIX.length && blob.subarray(0, WIN_V10_PREFIX.length).equals(WIN_V10_PREFIX)) {
        const localStatePath = stateDbPath
          ? localStatePathFromStateDb(stateDbPath)
          : path.join(process.env.APPDATA || "", "Code", "Local State");
        const aesKey = await windowsGetOrCreateAesKey(localStatePath);
        if (aesKey) {
          const result = windowsGcmDecrypt(blob, aesKey);
          if (result) {
            return result;
          }
        }
        return "";
      }
      // Legacy: raw DPAPI without prefix (older Chromium)
      return windowsUnprotect(blob);
    }
    if (platform === "darwin") {
      const pw = macReadMasterPassword(variant);
      if (!pw) {
        return "";
      }
      return aesDecrypt(blob, pw);
    }
    // linux — the version prefix alone doesn't tell us which password or
    // iteration count to use (modern Chromium uses v11+keyring+1iter, older
    // used v10+keyring+1003iter or v11+peanuts+1003iter). Try all combinations
    // that match the prefix until one decrypts successfully.
    const version = blob.subarray(0, 3).toString("latin1");
    const keyringPw = linuxReadMasterPassword(variant);
    const candidates = [];
    if (keyringPw) {
      candidates.push({ password: keyringPw, iterations: 1 });
      candidates.push({ password: keyringPw, iterations: 1003 });
    }
    candidates.push({ password: LINUX_BASIC_PASSWORD, iterations: 1 });
    candidates.push({ password: LINUX_BASIC_PASSWORD, iterations: 1003 });
    for (const c of candidates) {
      try {
        return aesDecrypt(blob, c.password, c.iterations);
      } catch {
        // wrong combination — try next
      }
    }
    return "";
  } catch {
    return "";
  }
}

/**
 * Whether the harness can produce a blob VS Code will decrypt on this machine.
 * @param {{ variant?: "stable" | "insiders" }} [opts]
 * @returns {boolean}
 */
export function isSecretEncryptionAvailable({ variant } = {}) {
  if (plaintextMode()) {
    return true;
  }
  const platform = os.platform();
  if (platform === "darwin") {
    return macReadMasterPassword(variant).length > 0;
  }
  if (platform === "win32") {
    // PowerShell is needed for DPAPI (to decrypt the AES key from Local State).
    return spawnSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.Major"], {
      encoding: "utf8",
    }).status === 0;
  }
  // linux: the basic_text backend always works ("peanuts"); a keyring is a bonus.
  return true;
}

/**
 * @param {"stable" | "insiders"} [variant]
 * @returns {string}
 */
export function secretEncryptionUnavailableMessage(variant) {
  const platform = os.platform();
  if (platform === "darwin") {
    return `Could not read VS Code's "${appNameFor(variant)} Safe Storage" key from the login Keychain, so the API key can't be stored where VS Code Chat reads it. Open VS Code once (it creates this key on first launch) and retry.`;
  }
  if (platform === "win32") {
    return "Windows DPAPI (via PowerShell) is unavailable, so the VS Code Chat API key can't be encrypted into VS Code's secret storage.";
  }
  return "Could not encrypt the VS Code Chat API key for VS Code's secret storage.";
}
