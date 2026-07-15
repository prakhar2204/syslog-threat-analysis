import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import Logs from './pages/Logs';
import Incidents, { IncidentDetail } from './pages/Incidents';
import Simulator from './pages/Simulator';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <AppProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/simulator" element={<Simulator />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
        </Routes>
      </AppProvider>
    </BrowserRouter>
  );
}
