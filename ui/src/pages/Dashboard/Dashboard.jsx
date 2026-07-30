import { useNavigate } from "react-router-dom";
import { FolderOpen, RefreshCw, Trash2, AlertCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import CreateBucketModal from "@/components/CreateBucketModal/CreateBucketModal";
import { useBuckets } from "@/context/BucketsContext";
import { useToast } from "@/context/ToastContext";
import { getConfiguredBaseUrl } from "@/lib/openlakeApi";
import { useState } from "react";

import "./Dashboard.css";

function Dashboard() {
  const navigate = useNavigate();
  const toast = useToast();
  const {
    buckets,
    loading,
    error,
    connection,
    refresh,
    refreshConnection,
    createBucket,
    deleteBucket,
  } = useBuckets();

  const [modalOpen, setModalOpen] = useState(false);
  const [deletingName, setDeletingName] = useState(null);

  async function handleCreateBucket(name) {
    try {
      await createBucket(name);
      toast.success(`Bucket "${name}" created`);
    } catch (err) {
      toast.error(err.message || "Failed to create bucket");
      throw err;
    }
  }

  async function handleDeleteBucket(name, e) {
    e.stopPropagation();
    if (!window.confirm(`Delete bucket "${name}"? It must be empty unless you force delete.`)) return;
    setDeletingName(name);
    try {
      await deleteBucket(name);
      toast.success(`Bucket "${name}" deleted`);
    } catch (err) {
      if (err.status === 409 || /not empty/i.test(err.message || "")) {
        if (window.confirm(`"${name}" isn't empty. Force delete anyway?`)) {
          try {
            await deleteBucket(name, { force: true });
            toast.success(`Bucket "${name}" force-deleted`);
          } catch (err2) {
            toast.error(err2.message || "Failed to force delete bucket");
          }
        }
      } else {
        toast.error(err.message || "Failed to delete bucket");
      }
    } finally {
      setDeletingName(null);
    }
  }

  async function handleRefresh() {
    await Promise.all([refresh(), refreshConnection()]);
  }

  return (
    <div className="home-page">
      <div className="home-header">
        <div>
          <h1>Buckets</h1>
          <p>
            Showing {buckets.length} bucket{buckets.length === 1 ? "" : "s"}
            {connection.ok !== null && (
              <span className={`health-badge health-${connection.ok ? "online" : "offline"}`}>
                {connection.ok ? "Backend online" : "Backend unreachable"}
              </span>
            )}
          </p>
        </div>

        <div className="home-header-actions">
          <Button variant="outline" onClick={handleRefresh} disabled={loading}>
            <RefreshCw size={16} className={loading ? "spin" : undefined} />
            Refresh
          </Button>
          <Button onClick={() => setModalOpen(true)}>+ Create Bucket</Button>
        </div>
      </div>

      <div className="base-url-readout">
        Talking to: <code>{getConfiguredBaseUrl() || `${window.location.origin} (VITE_OPENLAKE_BASE_URL is not set)`}</code>
      </div>

      {connection.ok === false && (
        <div className="connection-diagnostics">
          <AlertCircle size={16} />
          <div>
            <strong>Can't reach the OpenLake backend.</strong>
            <p>
              Tried: <code>{connection.resolvedUrl}</code>
              {connection.status ? ` (${connection.status})` : ""}
            </p>
            <p>
              Check that OpenLake is running at that address and that{" "}
              <code>VITE_OPENLAKE_BASE_URL</code> in your <code>.env</code> file points at it,
              then restart <code>npm run dev</code>.
            </p>
          </div>
        </div>
      )}

      {error && <p className="dashboard-error">{error}</p>}

      <p className="dashboard-note">
        Bucket listing isn't supported by this backend (GET / returns 501).
        Buckets you create here are remembered in this browser and verified
        with the server on each refresh.
      </p>

      {loading && buckets.length === 0 ? (
        <div className="empty-state">
          <p>Loading buckets…</p>
        </div>
      ) : buckets.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📁</div>
          <h3>No buckets found</h3>
          <p>Create your first bucket to get started.</p>
          <Button onClick={() => setModalOpen(true)}>Create Bucket</Button>
        </div>
      ) : (
        <table className="bucket-table">
          <thead>
            <tr>
              <th>Bucket</th>
              <th>Actions</th>
            </tr>
          </thead>

          <tbody>
            {buckets.map((bucket) => (
              <tr key={bucket.name} onClick={() => navigate(`/objects/${bucket.name}`)}>
                <td>{bucket.name}</td>
                <td className="bucket-row-actions">
                  <Button variant="outline">
                    <FolderOpen size={16} />
                    &nbsp;Open
                  </Button>
                  <Button
                    variant="destructive"
                    size="icon"
                    onClick={(e) => handleDeleteBucket(bucket.name, e)}
                    disabled={deletingName === bucket.name}
                    title="Delete bucket"
                  >
                    <Trash2 size={15} />
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <CreateBucketModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onCreate={handleCreateBucket}
      />
    </div>
  );
}

export default Dashboard;
