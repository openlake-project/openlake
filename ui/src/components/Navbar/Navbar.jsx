import "./Navbar.css";
import ProfileMenu from "../ProfileMenu/ProfileMenu";
import {
  FiBell,
  FiMoon,
  FiSun,
  FiUser,
} from "react-icons/fi";

import { useTheme } from "../../context/ThemeContext";
import { useState } from "react";

import NotificationPanel from "../NotificationPanel/NotificationPanel";

function Navbar() {
  const [showProfile, setShowProfile] = useState(false);
  const { darkMode, setDarkMode } = useTheme();

  const [showNotifications, setShowNotifications] = useState(false);

  return (

    <div className="navbar">

      <h2>OpenLake Dashboard</h2>

      <div className="navbar-right">

        <button
          className="icon-btn"
          onClick={() => setDarkMode(!darkMode)}
        >
          {darkMode ? <FiSun /> : <FiMoon />}
        </button>

        <button
          className="icon-btn"
          onClick={() =>
            setShowNotifications(!showNotifications)
          }
        >
          <FiBell />
        </button>

        <div
className="profile"
onClick={() => setShowProfile(!showProfile)}
>
          <FiUser />
          <span>Admin</span>
        </div>

      </div>

      <NotificationPanel open={showNotifications} />
      <ProfileMenu open={showProfile} />
    </div>

  );
}

export default Navbar;