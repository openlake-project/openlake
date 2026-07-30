import { useEffect, useState } from "react";
import { FiX } from "react-icons/fi";
import {
  getBucketLocation,
  getBucketVersioning,
  setBucketVersioning,
} from "@/lib/openlakeApi";
import { useToast } from "@/context/ToastContext";
import "./BucketDetailsModal.css";

function BucketDetailsModal({ open, onClose, bucket }) {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [location, setLocation] = useState(null);
  const [versioning, setVersioning] = useState(false);
  const [togglingVersioning, setTogglingVersioning] = useState(false);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        // GET /{bucket}?location and GET /{bucket}?versioning
        const [loc, ver] = await Promise.all([
          getBucketLocation(bucket).catch(() => "local"),
          getBucketVersioning(bucket).catch(() => false),
        ]);
        if (!cancelled) {
          setLocation(loc);
          setVersioning(ver);
        }
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load bucket details");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open, bucket]);

  if (!open) return null;

  async function handleToggleVersioning() {
    const next = !versioning;
    setTogglingVersioning(true);
    try {
      // PUT /{bucket}?versioning
      await setBucketVersioning(bucket, next);
      setVersioning(next);
      toast.success(`Versioning ${next ? "enabled" : "suspended"} for "${bucket}"`);
    } catch (err) {
      toast.error(err.message || "Failed to update versioning");
    } finally {
      setTogglingVersioning(false);
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal bucket-details-modal">
        <div className="modal-header">
          <h2>Bucket Details</h2>
          <button className="close-btn" onClick={onClose}>
            <FiX />
          </button>
        </div>

        {loading && <p className="bd-loading">Loading…</p>}
        {error && <p className="field-error">{error}</p>}

        {!loading && !error && (
          <dl className="bd-list">
            <div>
              <dt>Bucket</dt>
              <dd>{bucket}</dd>
            </div>
            <div>
              <dt>Region</dt>
              <dd>{location || "local"}</dd>
            </div>
            <div className="bd-versioning-row">
              <dt>Versioning</dt>
              <dd>
                <button
                  className={`bd-toggle ${versioning ? "bd-toggle-on" : ""}`}
                  onClick={handleToggleVersioning}
                  disabled={togglingVersioning}
                >
                  <span className="bd-toggle-knob" />
                </button>
                <span className="bd-toggle-label">
                  {togglingVersioning ? "Updating…" : versioning ? "Enabled" : "Suspended"}
                </span>
              </dd>
            </div>
          </dl>
        )}

        <div className="modal-footer">
          <button className="cancel-btn" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

export default BucketDetailsModal;
