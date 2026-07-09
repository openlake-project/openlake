import "./FolderTree.css";
import { FiFolder, FiFolderPlus } from "react-icons/fi";

function FolderTree({ folders, selectedFolder, onSelectFolder }) {
  return (
    <div className="folder-tree">

      <h3>Folders</h3>

      <ul>
        {folders.map((folder) => (
          <li
            key={folder}
            className={selectedFolder === folder ? "active-folder" : ""}
            onClick={() => onSelectFolder(folder)}
          >
            <FiFolder />
            {folder}
          </li>
        ))}
      </ul>

      <button className="new-folder-btn">
        <FiFolderPlus />
        New Folder
      </button>

    </div>
  );
}

export default FolderTree;