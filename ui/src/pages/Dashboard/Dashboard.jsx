import ProgressBar from "../../components/ProgressBar/ProgressBar";
import StatCard from "../../components/StatCard/StatCard";
import "./Dashboard.css";
import {
  FiDatabase,
  FiFolder,
  FiHardDrive,
  FiActivity,
} from "react-icons/fi";

function Dashboard() {
  return (
    <div className="dashboard">

      <h1>Dashboard</h1>

      <p className="subtitle">
        Welcome to OpenLake Storage Management
      </p>

      <div className="quick-actions">
        <button className="primary-btn">
          + Create Bucket
        </button>

        <button className="secondary-btn">
          Upload Object
        </button>

        <button className="secondary-btn">
          Refresh Cluster
        </button>
      </div>

      <div className="cards">

        <StatCard
          icon={<FiDatabase />}
          value="12"
          title="Buckets"
        />

        <StatCard
          icon={<FiFolder />}
          value="1,245"
          title="Objects"
        />

        <StatCard
          icon={<FiHardDrive />}
          value="62%"
          title="Storage Used"
        />

        <StatCard
          icon={<FiActivity />}
          value="Healthy"
          title="Cluster"
        />

      </div>

      <div className="info-grid">

        <div className="storage">

          <h2>Storage Usage</h2>

          <ProgressBar
            percentage={62}
            label="620 GB of 1 TB used"
          />

        </div>

        <div className="cluster-card">

          <h2>Cluster Health</h2>

          <div className="health">
            🟢 Healthy
          </div>

          <p><strong>Nodes Online:</strong> 3</p>

          <p><strong>Version:</strong> v0.4.2</p>

          <p><strong>Latency:</strong> 14 ms</p>

        </div>

      </div>

      <div className="table">

        <h2>Recent Buckets</h2>

        <table>

          <thead>

            <tr>
              <th>Bucket</th>
              <th>Objects</th>
              <th>Size</th>
              <th>Region</th>
              <th>Status</th>
              <th>Last Modified</th>
            </tr>

          </thead>

          <tbody>

            <tr>
              <td>customer-backups</td>
              <td>1,204</td>
              <td>24.3 GB</td>
              <td>local</td>
              <td>🟢 Healthy</td>
              <td>2 hours ago</td>
            </tr>

            <tr>
              <td>production-logs</td>
              <td>8,450</td>
              <td>72.8 GB</td>
              <td>local</td>
              <td>🟢 Healthy</td>
              <td>Today</td>
            </tr>

            <tr>
              <td>ml-datasets</td>
              <td>582</td>
              <td>118 GB</td>
              <td>us-east-1</td>
              <td>🟢 Healthy</td>
              <td>Yesterday</td>
            </tr>

            <tr>
              <td>website-assets</td>
              <td>1,824</td>
              <td>16.4 GB</td>
              <td>eu-west-1</td>
              <td>🟢 Healthy</td>
              <td>3 days ago</td>
            </tr>

            <tr>
              <td>analytics-data</td>
              <td>5,320</td>
              <td>88.1 GB</td>
              <td>ap-south-1</td>
              <td>🟢 Healthy</td>
              <td>1 week ago</td>
            </tr>

          </tbody>

        </table>

      </div>

    </div>
  );
}

export default Dashboard;