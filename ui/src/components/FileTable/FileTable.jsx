import "./FileTable.css";
import {
FiDownload,
FiTrash2,
FiFile,
FiEye
} from "react-icons/fi";

function FileTable({ files, onPreview }) {

return(

<div className="object-table">

<table>

<thead>

<tr>

<th>Name</th>
<th>Type</th>
<th>Size</th>
<th>Modified</th>
<th>Preview</th>
<th>Actions</th>

</tr>

</thead>

<tbody>

{files.map((file,index)=>(

<tr key={index}>

<td>

<div className="file-name">

<FiFile/>

{file.name}

</div>

</td>

<td>{file.type}</td>

<td>{file.size}</td>

<td>{file.modified}</td>

<td>

<button
className="icon-btn"
onClick={()=>onPreview(file)}
>

<FiEye/>

</button>

</td>

<td>

<button className="icon-btn">

<FiDownload/>

</button>

<button className="icon-btn delete">

<FiTrash2/>

</button>

</td>

</tr>

))}

</tbody>

</table>

</div>

);

}

export default FileTable;