import "./CreateBucketModal.css";
import { FiX } from "react-icons/fi";
import { useState } from "react";

/**
 * `onCreate(bucketName)` is called on submit and is expected to return a
 * Promise (Dashboard.jsx wires this to createBucket() + the local bucket
 * registry). Region/versioning are collected in the form for parity with
 * the reference UI, but the backend only exposes bucket creation via a
 * plain PUT /{bucket} - it has no create-time region or versioning
 * parameter - so those fields are informational only for now. Versioning
 * can still be set afterwards via PUT /{bucket}?versioning.
 */
function CreateBucketModal({ open, onClose, onCreate }) {
  const [name, setName] = useState("");
  const [region, setRegion] = useState("local");
  const [versioning, setVersioning] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  if (!open) return null;

  const nameError =
    name && !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(name)
      ? "Use 3-63 lowercase letters, numbers, dots or hyphens"
      : null;

  function reset() {
    setName("");
    setRegion("local");
    setVersioning(false);
    setError(null);
    setSubmitting(false);
  }

  function handleClose() {
    reset();
    onClose();
  }

  async function handleSubmit() {
    if (!name || nameError) return;
    setSubmitting(true);
    setError(null);
    try {
      await onCreate(name, { region, versioning });
      reset();
      onClose();
    } catch (err) {
      setError(err.message || "Failed to create bucket");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-overlay">
      <div className="modal">
        <div className="modal-header">
          <h2>Create Bucket</h2>
          <button className="close-btn" onClick={handleClose}>
            <FiX />
          </button>
        </div>

        <div className="form-group">
          <label>Bucket Name</label>
          <input
            type="text"
            placeholder="Enter bucket name"
            value={name}
            onChange={(e) => setName(e.target.value.trim())}
            autoFocus
          />
          {nameError && <p className="field-error">{nameError}</p>}
        </div>

        <div className="form-group">
          <label>Region</label>
          <select value={region} onChange={(e) => setRegion(e.target.value)}>
            <option value="local">local</option>
            <option value="us-east-1">us-east-1</option>
            <option value="eu-west-1">eu-west-1</option>
            <option value="ap-south-1">ap-south-1</option>
          </select>
        </div>

        <div className="checkbox">
          <input
            type="checkbox"
            checked={versioning}
            onChange={(e) => setVersioning(e.target.checked)}
          />
          <span>Enable Versioning</span>
        </div>

        {error && <p className="field-error modal-error">{error}</p>}

        <div className="modal-footer">
          <button className="cancel-btn" onClick={handleClose} disabled={submitting}>
            Cancel
          </button>
          <button
            className="create-btn"
            onClick={handleSubmit}
            disabled={!name || !!nameError || submitting}
          >
            {submitting ? "Creating…" : "Create Bucket"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default CreateBucketModal;
