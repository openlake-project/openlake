import { useState } from "react";
import FilePreview from "../../components/FilePreview/FilePreview";
import UploadModal from "../../components/UploadModal/UploadModal";
import "./ObjectBrowser.css";
import { useEffect } from "react";
import { useParams } from "react-router-dom";
import {
  FiUpload,
  FiRefreshCw,
  FiSearch,
} from "react-icons/fi";

import FolderTree from "../../components/FolderTree/FolderTree";
import FileTable from "../../components/FileTable/FileTable";

function ObjectBrowser() {
  const [openUpload, setOpenUpload] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const { bucketName } = useParams();

  const currentBucket = bucketName || "customer-backups";

  const bucketData = {
    "customer-backups": {
      Root: [
        { name: "invoice.pdf", type: "PDF", size: "2.4 MB", modified: "Today" },
        { name: "backup.zip", type: "ZIP", size: "14 GB", modified: "Yesterday" },
        { name: "archive.tar", type: "TAR", size: "7.8 GB", modified: "3 days ago" },
      ],
  
      Documents: [
        { name: "contract.docx", type: "DOCX", size: "1.3 MB", modified: "Today" },
        { name: "agreement.pdf", type: "PDF", size: "4.2 MB", modified: "Yesterday" },
      ],
  
      Images: [
        { name: "logo.png", type: "PNG", size: "620 KB", modified: "Today" },
        { name: "banner.jpg", type: "JPG", size: "2.8 MB", modified: "Yesterday" },
      ],
  
      Logs: [
        { name: "customer.log", type: "LOG", size: "320 MB", modified: "Today" },
      ],
    },
  
    "production-logs": {
      Root: [
        { name: "system.log", type: "LOG", size: "860 MB", modified: "Today" },
        { name: "access.log", type: "LOG", size: "420 MB", modified: "Today" },
      ],
  
      Documents: [
        { name: "deployment.docx", type: "DOCX", size: "900 KB", modified: "Yesterday" },
      ],
  
      Images: [
        { name: "architecture.png", type: "PNG", size: "1.2 MB", modified: "3 days ago" },
      ],
  
      Logs: [
        { name: "error.log", type: "LOG", size: "80 MB", modified: "1 hour ago" },
        { name: "nginx.log", type: "LOG", size: "240 MB", modified: "Today" },
      ],
    },
  
    "ml-datasets": {
      Root: [
        { name: "train.csv", type: "CSV", size: "42 GB", modified: "Yesterday" },
        { name: "test.csv", type: "CSV", size: "8 GB", modified: "Yesterday" },
      ],
  
      Documents: [
        { name: "readme.pdf", type: "PDF", size: "600 KB", modified: "Today" },
      ],
  
      Images: [
        { name: "sample.png", type: "PNG", size: "2.4 MB", modified: "Yesterday" },
      ],
  
      Logs: [
        { name: "training.log", type: "LOG", size: "650 MB", modified: "Today" },
      ],
    },
  };

  const [selectedFolder, setSelectedFolder] = useState("Root");

const folders = Object.keys(bucketData[currentBucket]);

const files =
  bucketData[currentBucket][selectedFolder];

  useEffect(() => {
    setSelectedFolder("Root");
  }, [currentBucket]);
  return (
    <div className="objects-page">

      <div className="page-header">

        <div>

          <h1>Object Browser</h1>

          <div className="breadcrumb">
            Home / Buckets / <strong>{currentBucket}</strong> / {selectedFolder}
          </div>

        </div>

        <button
className="upload-btn"
onClick={() => setOpenUpload(true)}
>
          <FiUpload />
          Upload Object
        </button>

      </div>

      <div className="toolbar">

        <div className="search-box">

          <FiSearch />

          <input
            type="text"
            placeholder="Search objects..."
          />

        </div>

        <button className="refresh-btn">
          <FiRefreshCw />
          Refresh
        </button>

      </div>

      <div className="browser-layout">

        <FolderTree
          folders={folders}
          selectedFolder={selectedFolder}
          onSelectFolder={setSelectedFolder}
        />

<FileTable
files={files}
onPreview={setSelectedFile}
/>

      </div>
      <UploadModal
open={openUpload}
onClose={() => setOpenUpload(false)}
/>
<FilePreview
file={selectedFile}
bucket={currentBucket}
folder={selectedFolder}
onClose={() => setSelectedFile(null)}
/>
    </div>
  );
}

export default ObjectBrowser;