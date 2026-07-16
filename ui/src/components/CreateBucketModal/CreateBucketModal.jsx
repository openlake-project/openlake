import "./CreateBucketModal.css";
import { FiX } from "react-icons/fi";

function CreateBucketModal({ open, onClose }) {
  if (!open) return null;

  return (
    <div className="modal-overlay">

      <div className="modal">

        <div className="modal-header">

          <h2>Create Bucket</h2>

          <button className="close-btn" onClick={onClose}>
            <FiX />
          </button>

        </div>

        <div className="form-group">

          <label>Bucket Name</label>

          <input
            type="text"
            placeholder="Enter bucket name"
          />

        </div>

        <div className="form-group">

          <label>Region</label>

          <select>

            <option>local</option>

            <option>us-east-1</option>

            <option>eu-west-1</option>

            <option>ap-south-1</option>

          </select>

        </div>

        <div className="checkbox">

          <input type="checkbox" />

          <span>Enable Versioning</span>

        </div>

        <div className="modal-footer">

          <button
            className="cancel-btn"
            onClick={onClose}
          >
            Cancel
          </button>

          <button
            className="create-btn"
            onClick={onClose}
          >
            Create Bucket
          </button>

        </div>

      </div>

    </div>
  );
}

export default CreateBucketModal;