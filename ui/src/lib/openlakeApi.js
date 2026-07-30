/**
 * OpenLake API client
 * -----------------------------------------------------------------------
 * Thin wrapper around fetch() for the OpenLake (MinIO/S3-like) backend.
 * Components should never call fetch() directly - go through here so the
 * request shape, auth headers, and error handling stay in one place.
 *
 * Base URL:
 *   Configure via the VITE_OPENLAKE_BASE_URL env var (see .env.example).
 *   Falls back to same-origin ("") if not set, so a dev proxy can be used.
 *
 * Auth:
 *   Not implemented by the backend yet. The request layer already reads a
 *   token from localStorage ("openlake_token") and, if present, attaches
 *   `Authorization: Bearer <token>` - so wiring up a login flow later is a
 *   matter of storing the token, nothing here needs to change.
 *   To switch to cookie-based auth later, set `credentials: "include"` in
 *   buildFetchOptions() below.
 */

const BASE_URL = import.meta.env.VITE_OPENLAKE_BASE_URL || "";

/** Generic error shape thrown by every helper in this file. */
export class OpenLakeApiError extends Error {
  constructor(message, { status, statusText, body, url } = {}) {
    super(message);
    this.name = "OpenLakeApiError";
    this.status = status;
    this.statusText = statusText;
    this.body = body;
    this.url = url;
  }
}

function getAuthHeaders() {
  const token = localStorage.getItem("openlake_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function buildUrl(path, query) {
  const url = new URL(
    (BASE_URL || window.location.origin) + path,
    window.location.origin
  );
  if (query) {
    Object.entries(query).forEach(([key, value]) => {
      if (value === undefined || value === null) return;
      // Support flag-style params (e.g. ?versioning) by passing "" as value
      url.searchParams.set(key, value === "" ? "" : String(value));
    });
  }
  // Flag-only params (no value) need special handling - URL always adds "="
  return url;
}

async function request(
  path,
  { method = "GET", query, headers = {}, body, signal, rawResponse } = {}
) {
  const url = buildUrl(path, query);

  let response;
  try {
    response = await fetch(url.toString(), {
      method,
      headers: { ...getAuthHeaders(), ...headers },
      body,
      signal,
    });
  } catch (networkErr) {
    throw new OpenLakeApiError(
      `Network error calling ${method} ${path}: ${networkErr.message}`,
      { url: url.toString() }
    );
  }

  if (response.status === 501) {
    throw new OpenLakeApiError(
      `${method} ${url} is not implemented by this OpenLake backend (501).`,
      { status: 501, statusText: response.statusText, url: url.toString() }
    );
  }

  if (!response.ok) {
    let bodyText = "";
    try {
      bodyText = await response.text();
    } catch {
      /* ignore */
    }
    // A 404 here almost always means one of two things: (a) VITE_OPENLAKE_BASE_URL
    // is unset/wrong, so this request hit the Vite dev server or the wrong host
    // instead of OpenLake, or (b) the route genuinely doesn't exist on this
    // backend build. Surfacing the exact URL makes it obvious which one it is.
    const hint =
      response.status === 404
        ? ` — check that VITE_OPENLAKE_BASE_URL (currently "${BASE_URL || "(not set, using " + window.location.origin + ")"}") points at your running OpenLake server.`
        : "";
    throw new OpenLakeApiError(
      `${method} ${url} failed with ${response.status} ${response.statusText}${hint}`,
      {
        status: response.status,
        statusText: response.statusText,
        body: bodyText,
        url: url.toString(),
      }
    );
  }

  if (rawResponse) return response;
  return response;
}

/* ------------------------------------------------------------------ */
/* Admin                                                                */
/* ------------------------------------------------------------------ */

export async function ping({ signal } = {}) {
  const res = await request("/openlake/admin/v1/ping", { signal });
  return safeJson(res);
}

export async function getConfig({ signal } = {}) {
  const res = await request("/openlake/admin/v1/config", { signal });
  return safeJson(res);
}

/** Resolved base URL, exposed for diagnostics UI. */
export function getConfiguredBaseUrl() {
  return BASE_URL || null;
}

/**
 * Runs a ping and reports back enough detail to self-diagnose a bad
 * VITE_OPENLAKE_BASE_URL - this is what the Dashboard's connection panel
 * uses instead of a bare try/catch around ping().
 */
export async function checkConnection() {
  const resolvedUrl = buildUrl("/openlake/admin/v1/ping").toString();
  try {
    const data = await ping();
    return { ok: true, resolvedUrl, data };
  } catch (err) {
    return {
      ok: false,
      resolvedUrl,
      status: err.status,
      message: err.message,
    };
  }
}

/* ------------------------------------------------------------------ */
/* Buckets                                                             */
/* ------------------------------------------------------------------ */

/**
 * There is no ListBuckets endpoint (GET / -> 501), so bucket discovery
 * is impossible from the backend alone. See src/lib/bucketRegistry.js
 * for the client-side registry that tracks buckets created through this
 * UI. This helper simply confirms whether a given bucket still exists.
 */
export async function bucketExists(bucket, { signal } = {}) {
  try {
    await request(`/${encodeURIComponent(bucket)}`, {
      method: "HEAD",
      signal,
    });
    return true;
  } catch (err) {
    if (err.status === 404) return false;
    throw err;
  }
}

export async function createBucket(bucket, { signal } = {}) {
  await request(`/${encodeURIComponent(bucket)}`, {
    method: "PUT",
    signal,
  });
  return { name: bucket };
}

export async function deleteBucket(bucket, { force = false, signal } = {}) {
  await request(`/${encodeURIComponent(bucket)}`, {
    method: "DELETE",
    query: force ? { force: 1 } : undefined,
    signal,
  });
}

export async function getBucketLocation(bucket, { signal } = {}) {
  const res = await request(`/${encodeURIComponent(bucket)}`, {
    query: { location: "" },
    signal,
  });
  const text = await res.text();
  return parseSimpleXmlValue(text, "LocationConstraint") || "local";
}

export async function getBucketVersioning(bucket, { signal } = {}) {
  const res = await request(`/${encodeURIComponent(bucket)}`, {
    query: { versioning: "" },
    signal,
  });
  const text = await res.text();
  return (parseSimpleXmlValue(text, "Status") || "Suspended") === "Enabled";
}

export async function setBucketVersioning(
  bucket,
  enabled,
  { signal } = {}
) {
  const body = `<?xml version="1.0" encoding="UTF-8"?>\n<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>${
    enabled ? "Enabled" : "Suspended"
  }</Status></VersioningConfiguration>`;
  await request(`/${encodeURIComponent(bucket)}`, {
    method: "PUT",
    query: { versioning: "" },
    headers: { "Content-Type": "application/xml" },
    body,
    signal,
  });
}

/* ------------------------------------------------------------------ */
/* Objects                                                              */
/* ------------------------------------------------------------------ */

/**
 * Lists objects in a bucket using ListObjectsV2 (?list-type=2).
 * Returns { objects: [{ key, size, lastModified, etag }], isTruncated, nextContinuationToken }
 */
export async function listObjects(
  bucket,
  { prefix, continuationToken, maxKeys, delimiter, signal } = {}
) {
  const res = await request(`/${encodeURIComponent(bucket)}`, {
    query: {
      "list-type": 2,
      prefix: prefix || undefined,
      "continuation-token": continuationToken || undefined,
      "max-keys": maxKeys || undefined,
      delimiter: delimiter || undefined,
    },
    signal,
  });
  const xmlText = await res.text();
  return parseListObjectsV2(xmlText);
}

export async function headObject(bucket, key, { signal } = {}) {
  const res = await request(
    `/${encodeURIComponent(bucket)}/${encodeKey(key)}`,
    { method: "HEAD", signal }
  );
  return {
    key,
    size: Number(res.headers.get("content-length")) || 0,
    lastModified: res.headers.get("last-modified") || null,
    etag: (res.headers.get("etag") || "").replaceAll('"', ""),
    contentType: res.headers.get("content-type") || null,
    // Not exposed by the backend today - kept as explicit placeholders
    // so the details panel has a stable shape to render against.
    tags: null,
    legalHold: null,
    retention: null,
  };
}

export function getObjectUrl(bucket, key) {
  return buildUrl(`/${encodeURIComponent(bucket)}/${encodeKey(key)}`).toString();
}

export async function downloadObject(bucket, key, { signal } = {}) {
  const res = await request(
    `/${encodeURIComponent(bucket)}/${encodeKey(key)}`,
    { method: "GET", signal }
  );
  return res.blob();
}

export async function deleteObject(bucket, key, { signal } = {}) {
  await request(`/${encodeURIComponent(bucket)}/${encodeKey(key)}`, {
    method: "DELETE",
    signal,
  });
}

export async function batchDeleteObjects(bucket, keys, { signal } = {}) {
  const body = `<?xml version="1.0" encoding="UTF-8"?>\n<Delete>${keys
    .map((k) => `<Object><Key>${escapeXml(k)}</Key></Object>`)
    .join("")}</Delete>`;
  const res = await request(`/${encodeURIComponent(bucket)}`, {
    method: "POST",
    headers: { "Content-Type": "application/xml" },
    body,
    signal,
  });
  return res.text();
}

/**
 * Simple (non-multipart) upload with progress reporting via XHR, since
 * fetch() does not expose upload progress events.
 */
export function uploadObject(
  bucket,
  key,
  file,
  { onProgress, contentType, signal } = {}
) {
  const url = buildUrl(
    `/${encodeURIComponent(bucket)}/${encodeKey(key)}`
  ).toString();

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", url, true);

    const authHeaders = getAuthHeaders();
    Object.entries(authHeaders).forEach(([k, v]) => xhr.setRequestHeader(k, v));
    xhr.setRequestHeader(
      "Content-Type",
      contentType || file.type || "application/octet-stream"
    );

    xhr.upload.onprogress = (evt) => {
      if (onProgress && evt.lengthComputable) {
        onProgress(Math.round((evt.loaded / evt.total) * 100));
      }
    };

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve({ key, etag: (xhr.getResponseHeader("etag") || "").replaceAll('"', "") });
      } else {
        reject(
          new OpenLakeApiError(
            `Upload failed with ${xhr.status} ${xhr.statusText}`,
            { status: xhr.status, statusText: xhr.statusText, url }
          )
        );
      }
    };
    xhr.onerror = () =>
      reject(new OpenLakeApiError("Network error during upload", { url }));

    if (signal) {
      signal.addEventListener("abort", () => xhr.abort());
    }

    xhr.send(file);
  });
}

/* --- Multipart upload (kept minimal; wire in when files exceed a size
   threshold, e.g. > 32 MB) --- */

export async function createMultipartUpload(bucket, key, { signal } = {}) {
  const res = await request(
    `/${encodeURIComponent(bucket)}/${encodeKey(key)}`,
    { method: "POST", query: { uploads: "" }, signal }
  );
  const text = await res.text();
  return parseSimpleXmlValue(text, "UploadId");
}

export function uploadPart(bucket, key, uploadId, partNumber, blob, { onProgress, signal } = {}) {
  const url = buildUrl(`/${encodeURIComponent(bucket)}/${encodeKey(key)}`, {
    partNumber,
    uploadId,
  }).toString();

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", url, true);
    const authHeaders = getAuthHeaders();
    Object.entries(authHeaders).forEach(([k, v]) => xhr.setRequestHeader(k, v));
    xhr.upload.onprogress = (evt) => {
      if (onProgress && evt.lengthComputable) {
        onProgress(Math.round((evt.loaded / evt.total) * 100));
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve({ partNumber, etag: (xhr.getResponseHeader("etag") || "").replaceAll('"', "") });
      } else {
        reject(new OpenLakeApiError(`Upload part failed with ${xhr.status}`, { status: xhr.status, url }));
      }
    };
    xhr.onerror = () => reject(new OpenLakeApiError("Network error uploading part", { url }));
    if (signal) signal.addEventListener("abort", () => xhr.abort());
    xhr.send(blob);
  });
}

export async function completeMultipartUpload(bucket, key, uploadId, parts, { signal } = {}) {
  const body = `<?xml version="1.0" encoding="UTF-8"?>\n<CompleteMultipartUpload>${parts
    .map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`)
    .join("")}</CompleteMultipartUpload>`;
  await request(`/${encodeURIComponent(bucket)}/${encodeKey(key)}`, {
    method: "POST",
    query: { uploadId },
    headers: { "Content-Type": "application/xml" },
    body,
    signal,
  });
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

function encodeKey(key) {
  // Encode each path segment but keep "/" as a real separator.
  return key.split("/").map(encodeURIComponent).join("/");
}

async function safeJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

function escapeXml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function parseSimpleXmlValue(xmlText, tagName) {
  const doc = new DOMParser().parseFromString(xmlText, "application/xml");
  const el = doc.getElementsByTagName(tagName)[0];
  return el ? el.textContent : null;
}

/**
 * Parses a standard S3 ListObjectsV2 XML response into a plain JS shape.
 * Expected structure (namespaced or not):
 * <ListBucketResult>
 *   <IsTruncated>false</IsTruncated>
 *   <Contents>
 *     <Key>...</Key><LastModified>...</LastModified><ETag>"..."</ETag><Size>123</Size>
 *   </Contents>
 *   ...
 *   <NextContinuationToken>...</NextContinuationToken>
 *   <CommonPrefixes><Prefix>folder/</Prefix></CommonPrefixes>
 * </ListBucketResult>
 */
export function parseListObjectsV2(xmlText) {
  const doc = new DOMParser().parseFromString(xmlText, "application/xml");

  const parseError = doc.getElementsByTagName("parsererror")[0];
  if (parseError) {
    throw new OpenLakeApiError("Failed to parse ListObjectsV2 XML response");
  }

  const contents = Array.from(doc.getElementsByTagName("Contents")).map((node) => ({
    key: textOf(node, "Key"),
    lastModified: textOf(node, "LastModified"),
    etag: (textOf(node, "ETag") || "").replaceAll('"', ""),
    size: Number(textOf(node, "Size")) || 0,
    storageClass: textOf(node, "StorageClass"),
  }));

  const commonPrefixes = Array.from(doc.getElementsByTagName("CommonPrefixes")).map(
    (node) => textOf(node, "Prefix")
  );

  const isTruncated = (parseSimpleXmlValue(xmlText, "IsTruncated") || "false") === "true";
  const nextContinuationToken = parseSimpleXmlValue(xmlText, "NextContinuationToken");

  return { objects: contents, commonPrefixes, isTruncated, nextContinuationToken };
}

function textOf(node, tagName) {
  const el = node.getElementsByTagName(tagName)[0];
  return el ? el.textContent : null;
}
