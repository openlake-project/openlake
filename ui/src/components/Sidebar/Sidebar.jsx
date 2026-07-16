import { NavLink } from "react-router-dom";
import {
  FiHome,
  FiDatabase,
  FiBarChart2,
  FiFolder,
  FiSettings,
} from "react-icons/fi";

import "./Sidebar.css";

function Sidebar() {
  return (
    <div className="sidebar">

      <div className="logo">
        OpenLake
      </div>

      <nav>

        <NavLink to="/" end className="nav-link">
          <FiHome />
          <span>Dashboard</span>
        </NavLink>

        <NavLink to="/buckets" className="nav-link">
          <FiDatabase />
          <span>Buckets</span>
        </NavLink>

        <NavLink to="/analytics" className="nav-link">
          <FiBarChart2 />
          <span>Analytics</span>
        </NavLink>

        <NavLink to="/objects/customer-backups" className="nav-link">
          <FiFolder />
          <span>Object Browser</span>
        </NavLink>

      </nav>

      <div className="bottom-menu">

        <NavLink to="/settings" className="nav-link">
          <FiSettings />
          <span>Settings</span>
        </NavLink>

      </div>

    </div>
  );
}

export default Sidebar;