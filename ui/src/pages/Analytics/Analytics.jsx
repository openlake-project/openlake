import "./Analytics.css";
import ChartCard from "../../components/ChartCard/ChartCard";

function Analytics() {

const buckets=[
{name:"Customer",value:72},
{name:"Logs",value:48},
{name:"Images",value:86},
{name:"Backups",value:63},
];

return(

<div className="analytics">

<h1>Storage Analytics</h1>

<p className="subtitle">
Monitor storage usage and cluster statistics
</p>

<div className="stats">

<div className="stat">
<h2>1.2 TB</h2>
<p>Total Storage</p>
</div>

<div className="stat">
<h2>18</h2>
<p>Buckets</p>
</div>

<div className="stat">
<h2>9,842</h2>
<p>Objects</p>
</div>

<div className="stat">
<h2>Healthy</h2>
<p>Cluster</p>
</div>

</div>

<div className="charts">

<ChartCard title="Bucket Usage">

{buckets.map(bucket=>(

<div
className="usage-row"
key={bucket.name}
>

<span>{bucket.name}</span>

<div className="bar">

<div
className="fill"
style={{width:`${bucket.value}%`}}
></div>

</div>

<span>{bucket.value}%</span>

</div>

))}

</ChartCard>

<ChartCard title="Cluster Summary">

<div className="summary">

<p>🟢 3 Nodes Online</p>

<p>⚡ Avg Latency: 14 ms</p>

<p>📦 Replication Enabled</p>

<p>🔒 Encryption Enabled</p>

<p>✔ Version: v0.4.2</p>

</div>

</ChartCard>

</div>

</div>

);

}

export default Analytics;