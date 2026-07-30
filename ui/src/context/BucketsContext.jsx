import { createContext, useCallback, useContext, useEffect, useState } from "react";
import {
  createBucket as apiCreateBucket,
  deleteBucket as apiDeleteBucket,
  bucketExists,
  checkConnection,
} from "@/lib/openlakeApi";
import { getKnownBuckets, addKnownBucket, removeKnownBucket } from "@/lib/bucketRegistry";

const BucketsContext = createContext(null);

export function BucketsProvider({ children }) {
  const [buckets, setBuckets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [connection, setConnection] = useState({ ok: null });

  // There is no ListBuckets endpoint on this backend (GET / -> 501), so we
  // track buckets created through this UI in localStorage and reconcile
  // with HEAD /{bucket} on every refresh - see src/lib/bucketRegistry.js.
  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const known = getKnownBuckets();
      const checked = await Promise.all(
        known.map(async (name) => {
          const exists = await bucketExists(name).catch(() => false);
          if (!exists) removeKnownBucket(name);
          return exists ? { name } : null;
        })
      );
      setBuckets(checked.filter(Boolean));
    } catch (err) {
      setError(err.message || "Failed to load buckets");
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshConnection = useCallback(async () => {
    const result = await checkConnection();
    setConnection(result);
    return result;
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (cancelled) return;
      await Promise.all([refresh(), refreshConnection()]);
    })();
    return () => {
      cancelled = true;
    };
  }, [refresh, refreshConnection]);

  const createBucket = useCallback(
    async (name) => {
      await apiCreateBucket(name);
      addKnownBucket(name);
      await refresh();
    },
    [refresh]
  );

  const deleteBucket = useCallback(
    async (name, { force = false } = {}) => {
      await apiDeleteBucket(name, { force });
      removeKnownBucket(name);
      await refresh();
    },
    [refresh]
  );

  return (
    <BucketsContext.Provider
      value={{
        buckets,
        loading,
        error,
        connection,
        refresh,
        refreshConnection,
        createBucket,
        deleteBucket,
      }}
    >
      {children}
    </BucketsContext.Provider>
  );
}

export function useBuckets() {
  const ctx = useContext(BucketsContext);
  if (!ctx) throw new Error("useBuckets must be used within a BucketsProvider");
  return ctx;
}
