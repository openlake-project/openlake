import { Bell, Moon, Sun } from "lucide-react";
import { useLocation, useParams } from "react-router-dom";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { useTheme } from "@/context/ThemeContext";
import { useBuckets } from "@/context/BucketsContext";

import "./Navbar.css";

function pageTitle(pathname, bucketName) {
  if (pathname === "/") return "Buckets";
  if (bucketName) return bucketName;
  return "OpenLake";
}

function Navbar() {
  const location = useLocation();
  const { bucketName } = useParams();
  const { darkMode, setDarkMode } = useTheme();
  const { connection } = useBuckets();

  return (
    <header className="navbar">
      <h2 className="page-title">{pageTitle(location.pathname, bucketName)}</h2>

      <div className="navbar-right">
        {connection.ok !== null && (
          <span
            className={`connection-dot ${connection.ok ? "dot-online" : "dot-offline"}`}
            title={connection.ok ? "Connected to OpenLake" : "Backend unreachable"}
          />
        )}

        <button
          className="icon-btn"
          onClick={() => setDarkMode(!darkMode)}
          title="Toggle theme"
        >
          {darkMode ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        <button className="icon-btn">
          <Bell size={18} />
        </button>

        <Avatar>
          <AvatarFallback>AR</AvatarFallback>
        </Avatar>
      </div>
    </header>
  );
}

export default Navbar;
