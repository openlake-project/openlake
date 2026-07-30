import "./Toast.css";

function Toast({ message, show }) {
  if (!show) return null;

  return (
    <div className="toast">
      ✅ {message}
    </div>
  );
}

export default Toast;