import { NavLink } from "react-router-dom";
import { FiHome, FiUser } from "react-icons/fi";
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
          <span>Home</span>
        </NavLink>
      </nav>

      <div className="bottom-menu">
        <div className="nav-link">
          <FiUser />
          <span>Ayush</span>
        </div>
      </div>
    </div>
  );
}

export default Sidebar;