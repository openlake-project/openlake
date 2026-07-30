import "./UploadModal.css";
import { FiUploadCloud, FiX } from "react-icons/fi";
import { useState } from "react";
import ProgressBar from "@/components/ProgressBar/ProgressBar";

/**
 * `onUpload(file, { onProgress })` is expected to return a Promise -
 * ObjectBrowser.jsx wires this to uploadObject() from src/lib/openlakeApi.js.
 */
function UploadModal({ open, onClose, onUpload }) {
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);

  if (!open) return null;

  function handleFile(e) {
    if (e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError(null);
    }
  }

  function reset() {
    setFile(null);
    setProgress(0);
    setUploading(false);
    setError(null);
  }

  function handleClose() {
    if (uploading) return; // don't allow closing mid-upload
    reset();
    onClose();
  }

  async function handleUpload() {
    if (!file) return;
    setUploading(true);
    setError(null);
    try {
      await onUpload(file, { onProgress: setProgress });
      reset();
      onClose();
    } catch (err) {
      setError(err.message || "Upload failed");
      setUploading(false);
    }
  }

  return (
    <div className="upload-overlay">
      <div className="upload-modal">
        <div className="upload-header">
          <h2>Upload Object</h2>
          <button className="close-btn" onClick={handleClose} disabled={uploading}>
            <FiX />
          </button>
        </div>

        <label className="drop-zone">
          <FiUploadCloud size={60} />
          <h3>Drag & Drop Files Here</h3>
          <p>or click to browse</p>
          <input type="file" onChange={handleFile} disabled={uploading} />
        </label>

        <div className="selected-file">
          {file ? `Selected: ${file.name}` : "No file selected"}
        </div>

        {uploading && (
          <ProgressBar percentage={progress} label={`Uploading… ${progress}%`} />
        )}

        {error && <p className="upload-error">{error}</p>}

        <div className="upload-footer">
          <button className="cancel-btn" onClick={handleClose} disabled={uploading}>
            Cancel
          </button>
          <button
            className="upload-btn-modal"
            onClick={handleUpload}
            disabled={!file || uploading}
          >
            {uploading ? "Uploading…" : "Upload"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default UploadModal;
