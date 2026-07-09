import "./Buckets.css";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FiPlus,
  FiSearch,
  FiTrash2,
  FiEye,
  FiDatabase,
} from "react-icons/fi";

import CreateBucketModal from "../../components/CreateBucketModal/CreateBucketModal";
import Toast from "../../components/Toast/Toast";

function Buckets() {
  const navigate = useNavigate();

  const [openModal, setOpenModal] = useState(false);
  const [showToast, setShowToast] = useState(false);

  return (
    <div className="buckets-page">

      <div className="bucket-header">

        <div>
          <h1>Buckets</h1>
          <p>Manage storage buckets across your cluster</p>
        </div>

        <button
          className="create-btn"
          onClick={() => {
            setOpenModal(true);
            setShowToast(true);

            setTimeout(() => {
              setShowToast(false);
            }, 2500);
          }}
        >
          <FiPlus />
          Create Bucket
        </button>

      </div>

      <div className="toolbar">

        <div className="search">

          <FiSearch />

          <input
            type="text"
            placeholder="Search buckets..."
          />

        </div>

      </div>

      <div className="bucket-table">

        <table>

          <thead>

            <tr>

              <th>Name</th>
              <th>Objects</th>
              <th>Size</th>
              <th>Region</th>
              <th>Status</th>
              <th>Actions</th>

            </tr>

          </thead>

          <tbody>

            <tr>

              <td>

                <div className="bucket-name">

                  <FiDatabase />

                  customer-backups

                </div>

              </td>

              <td>1204</td>

              <td>24.3 GB</td>

              <td>local</td>

              <td>

                <span className="badge">
                  Healthy
                </span>

              </td>

              <td>

                <button
                  className="icon-btn"
                  onClick={() =>
                    navigate("/objects/customer-backups")
                  }
                >
                  <FiEye />
                </button>

                <button className="icon-btn delete">
                  <FiTrash2 />
                </button>

              </td>

            </tr>

            <tr>

              <td>

                <div className="bucket-name">

                  <FiDatabase />

                  production-logs

                </div>

              </td>

              <td>8450</td>

              <td>72.8 GB</td>

              <td>local</td>

              <td>

                <span className="badge">
                  Healthy
                </span>

              </td>

              <td>

                <button
                  className="icon-btn"
                  onClick={() =>
                    navigate("/objects/production-logs")
                  }
                >
                  <FiEye />
                </button>

                <button className="icon-btn delete">
                  <FiTrash2 />
                </button>

              </td>

            </tr>

            <tr>

              <td>

                <div className="bucket-name">

                  <FiDatabase />

                  ml-datasets

                </div>

              </td>

              <td>582</td>

              <td>118 GB</td>

              <td>us-east-1</td>

              <td>

                <span className="badge">
                  Healthy
                </span>

              </td>

              <td>

                <button
                  className="icon-btn"
                  onClick={() =>
                    navigate("/objects/ml-datasets")
                  }
                >
                  <FiEye />
                </button>

                <button className="icon-btn delete">
                  <FiTrash2 />
                </button>

              </td>

            </tr>

          </tbody>

        </table>

      </div>

      <CreateBucketModal
        open={openModal}
        onClose={() => setOpenModal(false)}
      />

      <Toast
        show={showToast}
        message="Bucket created successfully"
      />

    </div>
  );
}

export default Buckets;