import { NavLink, useNavigate } from "react-router-dom";
import { FiHome, FiUser, FiPlus, FiSearch, FiDatabase } from "react-icons/fi";
import { useState } from "react";
import { useBuckets } from "@/context/BucketsContext";
import { useToast } from "@/context/ToastContext";
import CreateBucketModal from "@/components/CreateBucketModal/CreateBucketModal";
import "./Sidebar.css";

function Sidebar() {
  const navigate = useNavigate();
  const toast = useToast();
  const { buckets, loading, createBucket } = useBuckets();
  const [filter, setFilter] = useState("");
  const [modalOpen, setModalOpen] = useState(false);

  const visibleBuckets = filter
    ? buckets.filter((b) => b.name.toLowerCase().includes(filter.toLowerCase()))
    : buckets;

  async function handleCreate(name) {
    try {
      await createBucket(name);
      toast.success(`Bucket "${name}" created`);
      navigate(`/objects/${name}`);
    } catch (err) {
      toast.error(err.message || "Failed to create bucket");
      throw err;
    }
  }

  return (
    <div className="sidebar">
      <div>
        <div className="logo">OpenLake</div>

        <nav>
          <NavLink to="/" end className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
            <FiHome />
            <span>Home</span>
          </NavLink>
        </nav>

        <div className="sidebar-section">
          <button className="create-bucket-btn" onClick={() => setModalOpen(true)}>
            <FiPlus />
            Create Bucket
          </button>

          <div className="filter-buckets">
            <FiSearch size={14} />
            <input
              placeholder="Filter Buckets"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>

          <h4 className="sidebar-heading">Buckets</h4>

          <ul className="bucket-nav-list">
            {loading && buckets.length === 0 && (
              <li className="bucket-nav-empty">Loading…</li>
            )}
            {!loading && visibleBuckets.length === 0 && (
              <li className="bucket-nav-empty">No buckets yet</li>
            )}
            {visibleBuckets.map((b) => (
              <li key={b.name}>
                <NavLink
                  to={`/objects/${b.name}`}
                  className={({ isActive }) => `nav-link bucket-nav-link${isActive ? " active" : ""}`}
                >
                  <FiDatabase size={15} />
                  <span>{b.name}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="bottom-menu">
        <div className="nav-link">
          <FiUser />
          <span>Ayush</span>
        </div>
      </div>

      <CreateBucketModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onCreate={handleCreate}
      />
    </div>
  );
}

export default Sidebar;
