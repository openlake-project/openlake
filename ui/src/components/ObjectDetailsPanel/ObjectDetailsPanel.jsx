import { FiDownload, FiTrash2, FiFile, FiImage } from "react-icons/fi";
import { Button } from "@/components/ui/button";
import { formatBytes, formatDate, timeAgo } from "@/lib/format";
import { getObjectUrl } from "@/lib/openlakeApi";
import "./ObjectDetailsPanel.css";

/**
 * Right-hand "Object Info" panel. Opens when a row is clicked in the
 * object table (see ObjectBrowser.jsx). Metadata (`object`) is expected
 * to come from headObject() in src/lib/openlakeApi.js.
 */
function ObjectDetailsPanel({ object, bucket, loading, error, onDelete, onDownload, deleting }) {
  const isImage = object?.contentType?.startsWith("image/");
  return (
    <aside className="object-details-panel">
      {!object && !loading && (
        <div className="details-empty">
          <FiFile size={32} />
          <p>Select an object to view its details</p>
        </div>
      )}

      {loading && (
        <div className="details-empty">
          <p>Loading object info…</p>
        </div>
      )}

      {error && !loading && (
        <div className="details-empty details-error">
          <p>Couldn't load metadata for this object.</p>
          <span>{error}</span>
        </div>
      )}

      {object && !loading && !error && (
        <>
          <div className="details-title-row">
            {isImage ? <FiImage size={20} /> : <FiFile size={20} />}
            <h3 title={object.key}>{object.key.split("/").pop()}</h3>
          </div>

          {isImage && bucket && (
            <div className="details-preview">
              <img src={getObjectUrl(bucket, object.key)} alt={object.key} loading="lazy" />
            </div>
          )}

          <div className="details-actions">
            <Button variant="outline" size="sm" onClick={onDownload}>
              <FiDownload />
              Download
            </Button>
          </div>

          <Button
            variant="destructive"
            className="details-delete-btn"
            onClick={onDelete}
            disabled={deleting}
          >
            <FiTrash2 />
            {deleting ? "Deleting…" : "Delete"}
          </Button>

          <h4 className="details-section-heading">Object Info</h4>

          <dl className="details-list">
            <div>
              <dt>Name</dt>
              <dd>{object.key}</dd>
            </div>
            <div>
              <dt>Size</dt>
              <dd>{formatBytes(object.size)}</dd>
            </div>
            <div>
              <dt>Last Modified</dt>
              <dd title={formatDate(object.lastModified)}>
                {timeAgo(object.lastModified)}
              </dd>
            </div>
            <div>
              <dt>ETag</dt>
              <dd className="details-mono">{object.etag || "-"}</dd>
            </div>
            <div>
              <dt>Tags</dt>
              {/* Not exposed by the backend today - explicit placeholder */}
              <dd>{object.tags ?? "N/A"}</dd>
            </div>
            <div>
              <dt>Legal Hold</dt>
              {/* Not exposed by the backend today - explicit placeholder */}
              <dd>{object.legalHold ?? "Off"}</dd>
            </div>
            <div>
              <dt>Retention Policy</dt>
              {/* Not exposed by the backend today - explicit placeholder */}
              <dd>{object.retention ?? "None"}</dd>
            </div>
          </dl>

          <h4 className="details-section-heading">Metadata</h4>
          <dl className="details-list">
            <div>
              <dt>Content-Type</dt>
              <dd>{object.contentType || "application/octet-stream"}</dd>
            </div>
          </dl>
        </>
      )}
    </aside>
  );
}

export default ObjectDetailsPanel;
