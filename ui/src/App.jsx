import { Routes, Route } from "react-router-dom";
import MainLayout from "./layouts/MainLayout/MainLayout";
import Dashboard from "./pages/Dashboard/Dashboard";
import ObjectBrowser from "./pages/ObjectBrowser/ObjectBrowser";

function App() {
  return (
    <Routes>
      <Route path="/" element={<MainLayout />}>
        <Route index element={<Dashboard />} />
        <Route
          path="objects/:bucketName"
          element={<ObjectBrowser />}
        />
      </Route>
    </Routes>
  );
}

export default App;