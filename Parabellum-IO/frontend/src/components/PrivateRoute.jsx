import { Navigate } from 'react-router-dom';
import { getUser } from '../services/api';

export default function PrivateRoute({ children, adminOnly = false }) {
  const token = localStorage.getItem('token');
  if (!token) return <Navigate to="/login" replace />;

  if (adminOnly) {
    const user = getUser();
    if (!user || user.role !== 'admin') return <Navigate to="/dashboard" replace />;
  }
  return children;
}
