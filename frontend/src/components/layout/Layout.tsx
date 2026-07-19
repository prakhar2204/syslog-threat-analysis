import { Outlet } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';
import ThreatBanner from '../notifications/ThreatBanner';
import NotificationToast from '../notifications/NotificationToast';
import { useApp } from '../../context/AppContext';

export default function Layout() {
  const { state } = useApp();

  return (
    <div className="h-screen flex flex-col overflow-hidden">
      <Header />
      <ThreatBanner incident={state.latestCriticalIncident} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto p-4">
          <Outlet />
        </main>
      </div>
      <NotificationToast />
    </div>
  );
}
