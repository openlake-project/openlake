import { Routes, Route } from "react-router-dom";
import Analytics from "./pages/Analytics/Analytics";
import MainLayout from "./layouts/MainLayout/MainLayout";
import Dashboard from "./pages/Dashboard/Dashboard";
import Buckets from "./pages/Buckets/Buckets";
import ObjectBrowser from "./pages/ObjectBrowser/ObjectBrowser";
import Settings from "./pages/Settings/Settings";

function App() {
  return (
    <Routes>
      <Route path="/" element={<MainLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="buckets" element={<Buckets />} />

        <Route path="objects" element={<ObjectBrowser />} />
        <Route path="objects/:bucketName" element={<ObjectBrowser />} />

        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}

export default App;