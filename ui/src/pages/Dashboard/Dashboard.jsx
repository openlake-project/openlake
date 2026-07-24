import { useNavigate } from "react-router-dom";
import { FolderOpen } from "lucide-react";

import { Button } from "@/components/ui/button";


import "./Dashboard.css";

function Dashboard() {
  const navigate = useNavigate();

  const buckets = [
    {
      name: "customer-backups",
      objects: 1204,
      size: "24.3 GB",
      region: "local",
    },
    {
      name: "production-logs",
      objects: 8450,
      size: "72.8 GB",
      region: "local",
    },
    {
      name: "ml-datasets",
      objects: 582,
      size: "118 GB",
      region: "us-east-1",
    },
  ];

  return (
    <div className="home-page">

<div className="home-header">

<div>
  <h1>Buckets</h1>
  <p>Showing {buckets.length} buckets</p>
</div>

<Button>
  + Create Bucket
</Button>

</div>

      

{buckets.length === 0 ? (
  <div className="empty-state">

  <div className="empty-icon">
  📁
  </div>
  
  <h3>No buckets found</h3>
  
  <p>Create your first bucket to get started.</p>
  
  <Button>Create Bucket</Button>
  
  </div>
) : (
  <table className="bucket-table">
    <thead>
<tr>
<th>Bucket</th>
<th>Objects</th>
<th>Size</th>
<th>Region</th>
<th>Actions</th>
</tr>
</thead>

    <tbody>
      {buckets.map((bucket) => (
        <tr
          key={bucket.name}
          onClick={() => navigate(`/objects/${bucket.name}`)}
        >
          <td>{bucket.name}</td>
          <td>{bucket.objects}</td>
          <td>{bucket.size}</td>
          <td>{bucket.region}</td>
          <td>
          <Button variant="outline">
<FolderOpen size={16}/>
&nbsp;Open
</Button>
          </td>
        </tr>
      ))}
    </tbody>
  </table>
)}

    </div>
  );
}

export default Dashboard;