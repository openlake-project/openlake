import { useParams } from "react-router-dom";
import { Search } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import "./ObjectBrowser.css";

function ObjectBrowser() {
  const { bucketName } = useParams();

  const objects = {
    "customer-backups": [
      {
        name: "invoice.pdf",
        type: "PDF",
        size: "2.4 MB",
        modified: "Today",
      },
      {
        name: "backup.zip",
        type: "ZIP",
        size: "14 GB",
        modified: "Yesterday",
      },
      {
        name: "archive.tar",
        type: "TAR",
        size: "7.8 GB",
        modified: "3 days ago",
      },
    ],

    "production-logs": [
      {
        name: "system.log",
        type: "LOG",
        size: "860 MB",
        modified: "Today",
      },
      {
        name: "access.log",
        type: "LOG",
        size: "420 MB",
        modified: "Today",
      },
      {
        name: "error.log",
        type: "LOG",
        size: "80 MB",
        modified: "1 hour ago",
      },
    ],

    "ml-datasets": [
      {
        name: "train.csv",
        type: "CSV",
        size: "42 GB",
        modified: "Yesterday",
      },
      {
        name: "test.csv",
        type: "CSV",
        size: "8 GB",
        modified: "Yesterday",
      },
      {
        name: "model.pkl",
        type: "PKL",
        size: "650 MB",
        modified: "Today",
      },
    ],
  };

  const files = objects[bucketName] || [];

  return (
    <div className="objects-page">

      <div className="page-header">

        <div>
          <h1>{bucketName}</h1>
          <p>Browse and manage bucket objects</p>
        </div>

        <Button>
          Upload Object
        </Button>

      </div>

      <div className="search-area">

        <Search size={18} />

        <Input placeholder="Search objects..." />

      </div>
      {files.length === 0 ? (
  <div className="empty-state">
    <h3>No objects found</h3>
    <p>Upload your first object to this bucket.</p>
  </div>
) : (
  <table className="object-table">
    <thead>
      <tr>
        <th>Name</th>
        <th>Type</th>
        <th>Size</th>
        <th>Modified</th>
        <th></th>
      </tr>
    </thead>

    <tbody>
      {files.map((file) => (
        <tr key={file.name}>
          <td>{file.name}</td>
          <td>{file.type}</td>
          <td>{file.size}</td>
          <td>{file.modified}</td>
          <td>
            <Button variant="outline">
              Download
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

export default ObjectBrowser;