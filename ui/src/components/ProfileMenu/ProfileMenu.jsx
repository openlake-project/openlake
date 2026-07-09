import "./ProfileMenu.css";
import {
  FiUser,
  FiSettings,
  FiHelpCircle,
  FiLogOut,
} from "react-icons/fi";

function ProfileMenu({ open }) {
  if (!open) return null;

  return (
    <div className="profile-menu">

      <div className="profile-top">

        <div className="avatar-large">
          A
        </div>

        <div>
          <h3>Admin</h3>
          <p>admin@openlake.dev</p>
        </div>

      </div>

      <button>
        <FiUser />
        My Profile
      </button>

      <button>
        <FiSettings />
        Preferences
      </button>

      <button>
        <FiHelpCircle />
        Help Center
      </button>

      <button className="logout">
        <FiLogOut />
        Logout
      </button>

    </div>
  );
}

export default ProfileMenu;