import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import PrivateRoute from './components/PrivateRoute';

import LoginPage        from './pages/LoginPage';
import DashboardPage    from './pages/DashboardPage';
import PoliciesPage     from './pages/PoliciesPage';
import ToolsPage        from './pages/ToolsPage';
import ImportPage       from './pages/ImportPage';
import ScanPage         from './pages/ScanPage';
import CompliancePage   from './pages/CompliancePage';
import RiskRegisterPage from './pages/RiskRegisterPage';
import RiskPage from './pages/RiskPage';
import ReportsPage from './pages/ReportsPage';
import AdminPage from './pages/AdminPage';
import ComplianceReportPage from './pages/ComplianceReportPage';
import PipelinePage from './pages/PipelinePage';
import FindingsPage from './pages/FindingsPage';
import FinalReportPage from './pages/FinalReportPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"  element={<LoginPage />} />
        <Route path="/"       element={<Navigate to="/dashboard" replace />} />

        <Route path="/dashboard"     element={<PrivateRoute><DashboardPage /></PrivateRoute>} />
        <Route path="/policies"      element={<PrivateRoute><PoliciesPage /></PrivateRoute>} />
        <Route path="/tools"         element={<PrivateRoute><ToolsPage /></PrivateRoute>} />
        <Route path="/import"        element={<PrivateRoute><ImportPage /></PrivateRoute>} />
        <Route path="/scan"          element={<PrivateRoute><ScanPage /></PrivateRoute>} />
        <Route path="/compliance"     element={<PrivateRoute><CompliancePage /></PrivateRoute>} />
        <Route path="/risk-register" element={<PrivateRoute><RiskRegisterPage /></PrivateRoute>} />
        <Route path="/risk"          element={<PrivateRoute><RiskPage /></PrivateRoute>} />
        <Route path="/reports"       element={<PrivateRoute><ReportsPage /></PrivateRoute>} />
        <Route path="/compliance-report" element={<PrivateRoute><ComplianceReportPage /></PrivateRoute>} />
        <Route path="/pipeline"      element={<PrivateRoute><PipelinePage /></PrivateRoute>} />
        <Route path="/findings"      element={<PrivateRoute><FindingsPage /></PrivateRoute>} />
        <Route path="/final-report"  element={<PrivateRoute><FinalReportPage /></PrivateRoute>} />
        <Route path="/admin"         element={<PrivateRoute adminOnly><AdminPage /></PrivateRoute>} />

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
