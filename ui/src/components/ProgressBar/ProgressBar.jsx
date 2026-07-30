import "./ProgressBar.css";

function ProgressBar({ percentage, label }) {
  return (
    <div className="progress-container">

      <div className="progress-bar">

        <div
          className="progress-fill"
          style={{ width: `${percentage}%` }}
        ></div>

      </div>

      <p>{label}</p>

    </div>
  );
}

export default ProgressBar;