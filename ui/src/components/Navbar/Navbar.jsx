import { Search, Bell } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";

import "./Navbar.css";

function Navbar() {
  return (
    <header className="navbar">

      <h2 className="page-title">
        Buckets
      </h2>

      <div className="navbar-right">

        <div className="search-box">

          <Search size={18} />

          <Input placeholder="Search buckets..." />

        </div>

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