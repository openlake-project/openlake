import "./FilePreview.css";
import {
  FiDownload,
  FiTrash2,
  FiX,
  FiFile
} from "react-icons/fi";

function FilePreview({ file, bucket, folder, onClose }) {
  if (!file) return null;

  return (
    <div className="preview-overlay">

      <div className="preview-panel">

        <div className="preview-header">

          <h2>File Details</h2>

          <button
            className="close-preview"
            onClick={onClose}
          >
            <FiX />
          </button>

        </div>

        <div className="preview-icon">

          <FiFile size={70} />

        </div>

        <h3>{file.name}</h3>

        <div className="details">

          <div>
            <span>Type</span>
            <strong>{file.type}</strong>
          </div>

          <div>
            <span>Size</span>
            <strong>{file.size}</strong>
          </div>

          <div>
            <span>Modified</span>
            <strong>{file.modified}</strong>
          </div>

          <div>
            <span>Bucket</span>
            <strong>{bucket}</strong>
          </div>

          <div>
            <span>Folder</span>
            <strong>{folder}</strong>
          </div>

        </div>

        <div className="preview-actions">

          <button className="download">

            <FiDownload />

            Download

          </button>

          <button className="delete">

            <FiTrash2 />

            Delete

          </button>

        </div>

      </div>

    </div>
  );
}

export default FilePreview;