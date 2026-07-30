/**
 * Client-side bucket registry
 * -----------------------------------------------------------------------
 * The OpenLake backend does not implement ListBuckets (GET / -> 501) and
 * exposes no other bucket-discovery endpoint. That means there is no way
 * to ask the server "what buckets exist" - the frontend has to remember.
 *
 * This module keeps a small localStorage-backed list of bucket names that
 * were created (or manually added) through this UI. Dashboard.jsx uses
 * HEAD /{bucket} to confirm each entry still exists and silently drops
 * any that have been deleted out-of-band.
 *
 * This is a pragmatic workaround, not a substitute for a real ListBuckets
 * API - if the backend ever adds one, swap the call in Dashboard.jsx and
 * this file can be removed.
 */

const STORAGE_KEY = "openlake_known_buckets";

export function getKnownBuckets() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function addKnownBucket(name) {
  const current = getKnownBuckets();
  if (!current.includes(name)) {
    const updated = [...current, name];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  }
  return current;
}

export function removeKnownBucket(name) {
  const updated = getKnownBuckets().filter((b) => b !== name);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  return updated;
}
