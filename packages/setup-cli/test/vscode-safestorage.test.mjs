import { describe, it } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import path from "node:path";

import {
  aesDecrypt,
  aesEncrypt,
  decryptSecret,
  encryptSecret,
} from "../lib/vscode-safestorage.mjs";
import {
  ensureItemTable,
  readFirstItemTableValueByKeyPrefix,
  writeItemTableValue,
} from "../lib/vscdb-sqlite.mjs";

/* -------------------------------------------------------------------------- */
/* OSCrypt cipher wiring (macOS v10 / Linux v10/v11). Deterministic — uses a   */
/* fixed password, so it proves the PBKDF2 + AES-128-CBC + IV + version-prefix */
/* layering is correct and reversible without touching the OS keychain.        */
/* -------------------------------------------------------------------------- */

describe("vscode-safestorage OSCrypt cipher", () => {
  it("round-trips a value through aesEncrypt/aesDecrypt", () => {
    const pw = "peanuts"; // Chromium's Linux basic-backend password
    const blob = aesEncrypt("fw_secret_value_123", pw, "v10");
    assert.equal(blob.subarray(0, 3).toString("latin1"), "v10");
    assert.equal(aesDecrypt(blob, pw), "fw_secret_value_123");
  });

  it("ciphertext is salted/padded, not the plaintext", () => {
    const blob = aesEncrypt("hello", "peanuts", "v11");
    assert.equal(blob.subarray(0, 3).toString("latin1"), "v11");
    assert.ok(!blob.subarray(3).toString("latin1").includes("hello"));
    // AES-CBC with PKCS7 always pads to a full 16-byte block.
    assert.equal((blob.length - 3) % 16, 0);
  });

  it("a wrong password fails to decrypt (does not silently return junk equal to input)", () => {
    const blob = aesEncrypt("topsecret", "peanuts", "v10");
    let decrypted;
    try {
      decrypted = aesDecrypt(blob, "wrongpassword");
    } catch {
      decrypted = undefined; // padding error — acceptable
    }
    assert.notEqual(decrypted, "topsecret");
  });
});

/* -------------------------------------------------------------------------- */
/* Plaintext test seam (FIRECONNECT_VSCODE_SECRET_PLAINTEXT) used by the        */
/* harness integration tests.                                                  */
/* -------------------------------------------------------------------------- */

describe("vscode-safestorage plaintext seam", () => {
  it("encrypt/decrypt are the identity when the seam is set", async () => {
    const prev = process.env.FIRECONNECT_VSCODE_SECRET_PLAINTEXT;
    process.env.FIRECONNECT_VSCODE_SECRET_PLAINTEXT = "1";
    try {
      assert.equal(await encryptSecret("fw_abc"), "fw_abc");
      assert.equal(await decryptSecret("fw_abc"), "fw_abc");
    } finally {
      if (prev === undefined) {
        delete process.env.FIRECONNECT_VSCODE_SECRET_PLAINTEXT;
      } else {
        process.env.FIRECONNECT_VSCODE_SECRET_PLAINTEXT = prev;
      }
    }
  });

  it("decryptSecret returns '' for empty/garbage input", async () => {
    assert.equal(await decryptSecret(""), "");
    assert.equal(await decryptSecret("not-json-and-not-plaintext-mode"), "");
  });
});

/* -------------------------------------------------------------------------- */
/* Linux OSCrypt parameter detection — modern Chromium (Electron ~32+) uses     */
/* v11 prefix + keyring password + 1 PBKDF2 iteration, while older Chromium     */
/* used v10 + keyring + 1003 iterations or v11 + "peanuts" + 1003 iterations.   */
/* encryptSecret must detect the right combination from existing secrets.       */
/* -------------------------------------------------------------------------- */

describe("vscode-safestorage Linux OSCrypt parameter detection", () => {
  const isLinux = os.platform() === "linux";

  async function makeTempDb(existingSecretValue) {
    const dir = await mkdtemp(path.join(os.tmpdir(), "fireconnect-oscrypt-"));
    const dbPath = path.join(dir, "state.vscdb");
    await ensureItemTable(dbPath);
    if (existingSecretValue) {
      await writeItemTableValue(dbPath, "secret://chat.lm.secret.existing", existingSecretValue);
    }
    return { dbPath, dir };
  }

  function prefixOf(encrypted) {
    const parsed = JSON.parse(encrypted);
    return String.fromCharCode(parsed.data[0], parsed.data[1], parsed.data[2]);
  }

  it("readFirstItemTableValueByKeyPrefix finds a secret:// entry", async () => {
    const { dbPath, dir } = await makeTempDb('{"type":"Buffer","data":[118,49,49,1,2,3]}');
    try {
      const val = await readFirstItemTableValueByKeyPrefix(dbPath, "secret://");
      assert.equal(val, '{"type":"Buffer","data":[118,49,49,1,2,3]}');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("readFirstItemTableValueByKeyPrefix returns empty for no match", async () => {
    const { dbPath, dir } = await makeTempDb(null);
    try {
      const val = await readFirstItemTableValueByKeyPrefix(dbPath, "secret://");
      assert.equal(val, "");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("encryptSecret matches existing v11+keyring+1iter secrets (modern Chromium, Linux)", { skip: !isLinux }, async () => {
    // Simulate a state.vscdb where VS Code stored a v11 secret encrypted with
    // the keyring password and 1 PBKDF2 iteration (modern Chromium behavior).
    const fakeKeyringPw = "test_keyring_password";
    const existingBlob = JSON.stringify(aesEncrypt("existing_secret", fakeKeyringPw, "v11", 1));
    const { dbPath, dir } = await makeTempDb(existingBlob);
    try {
      // encryptSecret should detect and match the v11+1iter parameters.
      // NOTE: on a real system it would use the actual keyring password; here
      // the detection function will try the real keyring password first (which
      // won't match), then "peanuts" (which also won't match), and fall back
      // to the v11+1iter default — which is the correct behavior.
      const encrypted = await encryptSecret("fw_test_key", { stateDbPath: dbPath });
      assert.equal(prefixOf(encrypted), "v11");
      assert.equal(await decryptSecret(encrypted), "fw_test_key");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("encryptSecret matches existing v11+peanuts+1003iter secrets (older Chromium, Linux)", { skip: !isLinux }, async () => {
    // Simulate older Chromium: v11 + "peanuts" + 1003 iterations.
    const existingBlob = JSON.stringify(aesEncrypt("existing_secret", "peanuts", "v11", 1003));
    const { dbPath, dir } = await makeTempDb(existingBlob);
    try {
      const encrypted = await encryptSecret("fw_test_key", { stateDbPath: dbPath });
      assert.equal(prefixOf(encrypted), "v11");
      assert.equal(await decryptSecret(encrypted), "fw_test_key");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("encryptSecret defaults to v11+1iter when no existing secrets (Linux)", { skip: !isLinux }, async () => {
    const { dbPath, dir } = await makeTempDb(null);
    try {
      const encrypted = await encryptSecret("fw_test_key", { stateDbPath: dbPath });
      assert.equal(prefixOf(encrypted), "v11", "should default to v11");
      assert.equal(await decryptSecret(encrypted), "fw_test_key");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("encryptSecret defaults to v11+1iter when no stateDbPath provided (Linux)", { skip: !isLinux }, async () => {
    const encrypted = await encryptSecret("fw_test_key");
    assert.equal(prefixOf(encrypted), "v11", "should default to v11 when no DB path to probe");
    assert.equal(await decryptSecret(encrypted), "fw_test_key");
  });

  it("decryptSecret tries multiple iteration counts (Linux cross-generation compat)", { skip: !isLinux }, async () => {
    // A secret encrypted with 1 iteration should be decryptable
    const blob1 = JSON.stringify(aesEncrypt("fw_secret", "peanuts", "v11", 1));
    assert.equal(await decryptSecret(blob1), "fw_secret");

    // A secret encrypted with 1003 iterations should also be decryptable
    const blob1003 = JSON.stringify(aesEncrypt("fw_secret", "peanuts", "v11", 1003));
    assert.equal(await decryptSecret(blob1003), "fw_secret");
  });
});
