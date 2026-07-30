import { useParams } from "react-router-dom";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Search,
  RefreshCw,
  Upload as UploadIcon,
  Folder,
  Trash2,
  Copy,
  Info,
  ArrowUp,
  ArrowDown,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import UploadModal from "@/components/UploadModal/UploadModal";
import ObjectDetailsPanel from "@/components/ObjectDetailsPanel/ObjectDetailsPanel";
import BucketDetailsModal from "@/components/BucketDetailsModal/BucketDetailsModal";
import { useToast } from "@/context/ToastContext";
import {
  listObjects,
  headObject,
  uploadObject,
  deleteObject,
  downloadObject,
  batchDeleteObjects,
} from "@/lib/openlakeApi";
import { formatBytes, formatDate } from "@/lib/format";

import "./ObjectBrowser.css";

function ObjectBrowser() {
  const { bucketName } = useParams();
  const toast = useToast();

  const [objects, setObjects] = useState([]);
  const [folders, setFolders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // "Folder" navigation is simulated via the S3 delimiter convention:
  // listObjects(..., { delimiter: "/" }) groups keys under the current
  // prefix into CommonPrefixes (folders) vs Contents (files at this level).
  const [currentPath, setCurrentPath] = useState(""); // e.g. "images/cars/"

  const [searchInput, setSearchInput] = useState("");

  const [uploadOpen, setUploadOpen] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const dragCounter = useRef(0);

  const [selectedKey, setSelectedKey] = useState(null);
  const [selectedObject, setSelectedObject] = useState(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsError, setDetailsError] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const [checkedKeys, setCheckedKeys] = useState(() => new Set());

  const [sort, setSort] = useState({ column: "name", direction: "asc" });
  const [bucketDetailsOpen, setBucketDetailsOpen] = useState(false);

  const loadObjects = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // GET /{bucket}?list-type=2&prefix=...&delimiter=/
      const { objects: items, commonPrefixes } = await listObjects(bucketName, {
        prefix: currentPath || undefined,
        delimiter: "/",
      });
      // The prefix itself (a zero-byte "folder marker" object) shouldn't
      // show up as a file row.
      setObjects(items.filter((o) => o.key !== currentPath));
      setFolders(commonPrefixes || []);
    } catch (err) {
      setError(err.message || "Failed to list objects");
    } finally {
      setLoading(false);
    }
  }, [bucketName, currentPath]);

  useEffect(() => {
    let cancelled = false;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional: reset selection when bucket/path changes
    setSelectedKey(null);
    setSelectedObject(null);
    setCheckedKeys(new Set());
    (async () => {
      if (!cancelled) await loadObjects();
    })();
    return () => {
      cancelled = true;
    };
  }, [loadObjects]);

  // Reset to bucket root whenever the bucket itself changes.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional: reset path/search when navigating to a different bucket
    setCurrentPath("");
    setSearchInput("");
  }, [bucketName]);

  const query = searchInput.trim().toLowerCase();
  const visibleFolders = (query
    ? folders.filter((f) => f.toLowerCase().includes(query))
    : folders
  ).slice().sort((a, b) => a.localeCompare(b));

  const filteredObjects = query
    ? objects.filter((o) => o.key.toLowerCase().includes(query))
    : objects;

  const visibleObjects = filteredObjects.slice().sort((a, b) => {
    const dir = sort.direction === "asc" ? 1 : -1;
    if (sort.column === "size") return (a.size - b.size) * dir;
    if (sort.column === "modified")
      return (new Date(a.lastModified) - new Date(b.lastModified)) * dir;
    return a.key.localeCompare(b.key) * dir;
  });

  function toggleSort(column) {
    setSort((prev) =>
      prev.column === column
        ? { column, direction: prev.direction === "asc" ? "desc" : "asc" }
        : { column, direction: "asc" }
    );
  }

  function sortIcon(column) {
    if (sort.column !== column) return null;
    return sort.direction === "asc" ? <ArrowUp size={12} /> : <ArrowDown size={12} />;
  }

  const breadcrumbs = [
    { label: bucketName, path: "" },
    ...currentPath
      .split("/")
      .filter(Boolean)
      .map((segment, idx, arr) => ({
        label: segment,
        path: arr.slice(0, idx + 1).join("/") + "/",
      })),
  ];

  function enterFolder(prefix) {
    setCurrentPath(prefix);
  }

  async function copyCurrentPath() {
    const text = `${bucketName}/${currentPath}`;
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Path copied to clipboard");
    } catch {
      toast.error("Couldn't copy to clipboard");
    }
  }

  async function handleSelectRow(key) {
    setSelectedKey(key);
    setSelectedObject(null);
    setDetailsError(null);
    setDetailsLoading(true);
    try {
      // HEAD /{bucket}/{key} - object metadata for the details panel.
      const meta = await headObject(bucketName, key);
      setSelectedObject(meta);
    } catch (err) {
      setDetailsError(err.message || "Failed to load object metadata");
    } finally {
      setDetailsLoading(false);
    }
  }

  async function doUpload(file, onProgress) {
    const key = currentPath ? `${currentPath}${file.name}` : file.name;
    await uploadObject(bucketName, key, file, { onProgress });
  }

  async function handleUploadFromModal(file, { onProgress }) {
    try {
      await doUpload(file, onProgress);
      toast.success(`Uploaded "${file.name}"`);
      await loadObjects();
    } catch (err) {
      toast.error(err.message || `Failed to upload "${file.name}"`);
      throw err;
    }
  }

  async function handleFilesDropped(fileList) {
    const files = Array.from(fileList);
    if (files.length === 0) return;
    for (const file of files) {
      try {
        await doUpload(file, null);
        toast.success(`Uploaded "${file.name}"`);
      } catch (err) {
        toast.error(err.message || `Failed to upload "${file.name}"`);
      }
    }
    await loadObjects();
  }

  function onDragEnter(e) {
    e.preventDefault();
    dragCounter.current += 1;
    setDragActive(true);
  }
  function onDragLeave(e) {
    e.preventDefault();
    dragCounter.current -= 1;
    if (dragCounter.current <= 0) setDragActive(false);
  }
  function onDragOver(e) {
    e.preventDefault();
  }
  function onDrop(e) {
    e.preventDefault();
    dragCounter.current = 0;
    setDragActive(false);
    if (e.dataTransfer.files?.length) {
      handleFilesDropped(e.dataTransfer.files);
    }
  }

  async function handleDelete(key) {
    if (!window.confirm(`Delete "${key}"? This cannot be undone.`)) return;
    setDeleting(true);
    try {
      await deleteObject(bucketName, key);
      toast.success(`Deleted "${key}"`);
      if (selectedKey === key) {
        setSelectedKey(null);
        setSelectedObject(null);
      }
      await loadObjects();
    } catch (err) {
      toast.error(err.message || "Failed to delete object");
    } finally {
      setDeleting(false);
    }
  }

  async function handleBatchDelete() {
    const keys = Array.from(checkedKeys);
    if (keys.length === 0) return;
    if (!window.confirm(`Delete ${keys.length} selected object(s)? This cannot be undone.`)) return;
    try {
      // POST /{bucket} with a <Delete> XML body - batch delete.
      await batchDeleteObjects(bucketName, keys);
      toast.success(`Deleted ${keys.length} object(s)`);
      setCheckedKeys(new Set());
      if (selectedKey && keys.includes(selectedKey)) {
        setSelectedKey(null);
        setSelectedObject(null);
      }
      await loadObjects();
    } catch (err) {
      toast.error(err.message || "Batch delete failed");
    }
  }

  async function handleDownload(key) {
    try {
      const blob = await downloadObject(bucketName, key);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = key.split("/").pop();
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.error(err.message || "Failed to download object");
    }
  }

  function toggleChecked(key) {
    setCheckedKeys((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }

  function toggleCheckAll() {
    setCheckedKeys((prev) =>
      prev.size === visibleObjects.length ? new Set() : new Set(visibleObjects.map((o) => o.key))
    );
  }

  const allChecked = visibleObjects.length > 0 && checkedKeys.size === visibleObjects.length;

  return (
    <div
      className="objects-page-layout"
      onDragEnter={onDragEnter}
      onDragLeave={onDragLeave}
      onDragOver={onDragOver}
      onDrop={onDrop}
    >
      <div className="objects-page">
        <div className="page-header">
          <div>
            <h1>{bucketName}</h1>
            <p>Browse and manage bucket objects</p>
          </div>

          <div className="page-header-actions">
            <Button variant="outline" onClick={() => setBucketDetailsOpen(true)}>
              <Info size={16} />
              Bucket Details
            </Button>
            <Button variant="outline" onClick={loadObjects} disabled={loading}>
              <RefreshCw size={16} className={loading ? "spin" : undefined} />
              Refresh
            </Button>
            <Button onClick={() => setUploadOpen(true)}>
              <UploadIcon size={16} />
              Upload Object
            </Button>
          </div>
        </div>

        <div className="breadcrumbs">
          {breadcrumbs.map((crumb, idx) => (
            <span key={crumb.path}>
              {idx > 0 && <span className="crumb-sep">/</span>}
              <button className="crumb-btn" onClick={() => enterFolder(crumb.path)}>
                {crumb.label}
              </button>
            </span>
          ))}
          <button className="copy-path-btn" onClick={copyCurrentPath} title="Copy path">
            <Copy size={13} />
          </button>
        </div>

        <div className="search-area">
          <Search size={18} />
          <Input
            placeholder="Start typing to filter objects in this folder…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </div>

        {error && <p className="dashboard-error">{error}</p>}

        {checkedKeys.size > 0 && (
          <div className="batch-bar">
            <span>{checkedKeys.size} selected</span>
            <Button variant="destructive" size="sm" onClick={handleBatchDelete}>
              <Trash2 size={14} />
              Delete selected
            </Button>
          </div>
        )}

        {loading ? (
          <div className="empty-state">
            <p>Loading objects…</p>
          </div>
        ) : visibleFolders.length === 0 && visibleObjects.length === 0 ? (
          <div className="empty-state">
            <h3>No objects found</h3>
            <p>Upload your first object here, or drag & drop files onto this page.</p>
          </div>
        ) : (
          <table className="object-table">
            <thead>
              <tr>
                <th className="col-check">
                  <input type="checkbox" checked={allChecked} onChange={toggleCheckAll} />
                </th>
                <th className="sortable-th" onClick={() => toggleSort("name")}>
                  Name {sortIcon("name")}
                </th>
                <th className="sortable-th" onClick={() => toggleSort("size")}>
                  Size {sortIcon("size")}
                </th>
                <th className="sortable-th" onClick={() => toggleSort("modified")}>
                  Last Modified {sortIcon("modified")}
                </th>
                <th></th>
              </tr>
            </thead>

            <tbody>
              {visibleFolders.map((folderPrefix) => (
                <tr key={folderPrefix} className="folder-row" onClick={() => enterFolder(folderPrefix)}>
                  <td></td>
                  <td>
                    <span className="folder-name">
                      <Folder size={15} />
                      {folderPrefix.replace(currentPath, "").replace(/\/$/, "")}
                    </span>
                  </td>
                  <td>—</td>
                  <td>—</td>
                  <td></td>
                </tr>
              ))}

              {visibleObjects.map((obj) => (
                <tr
                  key={obj.key}
                  className={selectedKey === obj.key ? "row-selected" : ""}
                  onClick={() => handleSelectRow(obj.key)}
                >
                  <td onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={checkedKeys.has(obj.key)}
                      onChange={() => toggleChecked(obj.key)}
                    />
                  </td>
                  <td>{obj.key.replace(currentPath, "")}</td>
                  <td>{formatBytes(obj.size)}</td>
                  <td>{formatDate(obj.lastModified)}</td>
                  <td>
                    <Button
                      variant="outline"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDownload(obj.key);
                      }}
                    >
                      Download
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {dragActive && (
          <div className="drop-overlay">
            <UploadIcon size={40} />
            <p>Drop files to upload to /{currentPath || ""}</p>
          </div>
        )}
      </div>

      <ObjectDetailsPanel
        object={selectedObject}
        bucket={bucketName}
        loading={detailsLoading}
        error={detailsError}
        deleting={deleting}
        onDelete={() => selectedKey && handleDelete(selectedKey)}
        onDownload={() => selectedKey && handleDownload(selectedKey)}
      />

      <UploadModal
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        onUpload={handleUploadFromModal}
      />

      <BucketDetailsModal
        open={bucketDetailsOpen}
        onClose={() => setBucketDetailsOpen(false)}
        bucket={bucketName}
      />
    </div>
  );
}

export default ObjectBrowser;
