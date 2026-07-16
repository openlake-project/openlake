import "./NotificationPanel.css";
import {
  FiBell,
  FiCheckCircle,
  FiUpload,
  FiAlertCircle,
  FiDatabase,
} from "react-icons/fi";

function NotificationPanel({ open }) {
  if (!open) return null;

  return (
    <div className="notification-panel">

      <div className="notification-header">
        <FiBell />
        <h3>Notifications</h3>
      </div>

      <div className="notification-item">
        <FiDatabase className="green" />
        <div>
          <h4>Bucket Created</h4>
          <p>customer-backups • 2 min ago</p>
        </div>
      </div>

      <div className="notification-item">
        <FiUpload className="blue" />
        <div>
          <h4>Upload Complete</h4>
          <p>report.pdf uploaded successfully</p>
        </div>
      </div>

      <div className="notification-item">
        <FiAlertCircle className="orange" />
        <div>
          <h4>Storage Warning</h4>
          <p>Storage usage reached 80%</p>
        </div>
      </div>

      <div className="notification-item">
        <FiCheckCircle className="green" />
        <div>
          <h4>Cluster Healthy</h4>
          <p>All nodes are online</p>
        </div>
      </div>

    </div>
  );
}

export default NotificationPanel;