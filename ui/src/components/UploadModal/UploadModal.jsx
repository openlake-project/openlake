import "./UploadModal.css";
import { FiUploadCloud, FiX } from "react-icons/fi";
import { useState } from "react";

function UploadModal({ open, onClose }) {
  const [fileName, setFileName] = useState("");

  if (!open) return null;

  function handleFile(e) {
    if (e.target.files.length > 0) {
      setFileName(e.target.files[0].name);
    }
  }

  return (
    <div className="upload-overlay">

      <div className="upload-modal">

        <div className="upload-header">

          <h2>Upload Object</h2>

          <button className="close-btn" onClick={onClose}>
            <FiX />
          </button>

        </div>

        <label className="drop-zone">

          <FiUploadCloud size={60} />

          <h3>Drag & Drop Files Here</h3>

          <p>or click to browse</p>

          <input
            type="file"
            onChange={handleFile}
          />

        </label>

        <div className="selected-file">

          {fileName
            ? `Selected: ${fileName}`
            : "No file selected"}

        </div>

        <div className="upload-footer">

          <button
            className="cancel-btn"
            onClick={onClose}
          >
            Cancel
          </button>

          <button
            className="upload-btn-modal"
            onClick={onClose}
          >
            Upload
          </button>

        </div>

      </div>

    </div>
  );
}

export default UploadModal;