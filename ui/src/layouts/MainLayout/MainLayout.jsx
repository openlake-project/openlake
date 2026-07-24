import Sidebar from "../../components/Sidebar/Sidebar";
import Navbar from "../../components/Navbar/Navbar";
import { Outlet } from "react-router-dom";

function MainLayout() {
  return (
    <div style={{ display: "flex", height: "100vh" }}>
      <div
        style={{
          width: "240px",
          background: "#f8fafc",
          padding: "20px",
          borderRight: "1px solid #ddd",
        }}
      >
        <Sidebar />
      </div>

      <div style={{ flex: 1 }}>
        <Navbar />

        <div
style={{
padding:"35px",
background:"#f8fafc",
height:"calc(100vh - 70px)",
overflow:"auto"
}}
>
          <Outlet />
        </div>
      </div>
    </div>
  );
}

export default MainLayout;