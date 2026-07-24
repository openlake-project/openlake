import "./StatCard.css";

function StatCard({ icon, value, title }) {
  return (
    <div className="stat-card">

      <div className="icon">
        {icon}
      </div>

      <h2>{value}</h2>

      <p>{title}</p>

    </div>
  );
}

export default StatCard;