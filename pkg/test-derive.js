#!/usr/bin/env node
/*
 * Minimal Node.js test for the full Orchard key/address derivation pipeline using a BIP39 mnemonic.
 *
 * Steps:
 *   1) derive_spending_key(seed: Uint8Array, coinType: number, account: number) -> spendingKey
 *   2) derive_full_viewing_key(spendingKey: Uint8Array) -> fullViewingKey
 *   3) derive_address(fullViewingKey: Uint8Array, diversifierIndex: number) -> rawAddress
 *
 * Prerequisites:
 *   npm install bip39
 *   node --experimental-wasm-modules test-derive.js
 */
import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import * as orchard from './orchard_bg.js';
import bip39 from 'bip39';

// In ES modules, compute __dirname relative to this file
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  // Load and instantiate the WebAssembly module manually
  // Resolve the .wasm path relative to this script's directory
  const wasmPath = path.resolve(__dirname, 'orchard_bg.wasm');
  const wasmBytes = await readFile(wasmPath);
  // Provide the two JS functions the .wasm expects as imports
  const importObject = {
    './orchard_bg.js': {
      __wbindgen_string_new: orchard.__wbindgen_string_new,
      __wbindgen_object_drop_ref: orchard.__wbindgen_object_drop_ref,
    },
  };
  const { instance } = await WebAssembly.instantiate(wasmBytes, importObject);
  orchard.__wbg_set_wasm(instance.exports);

  // Example BIP39 mnemonic (12 words)
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  // Derive a 64-byte seed from the mnemonic
  const seedBuffer = await bip39.mnemonicToSeed(mnemonic);
  const seed = new Uint8Array(seedBuffer);

  const coinType = 1;
  const account = 0;

  // Derive the Orchard spending key
  const spendingKey = orchard.derive_spending_key(seed, coinType, account);
  console.log('Spending key (hex):', Buffer.from(spendingKey).toString('hex'));

  // Derive the full viewing key from the spending key
  const fullViewingKey = orchard.derive_full_viewing_key(spendingKey);
  console.log('Full viewing key (hex):', Buffer.from(fullViewingKey).toString('hex'));

  // Derive a raw Orchard payment address (using diversifier index = 0)
  const diversifierIndex = 0;
  const rawAddress = orchard.derive_address(fullViewingKey, diversifierIndex);
  console.log('Raw address (hex):', Buffer.from(rawAddress).toString('hex'));
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});