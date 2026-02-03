import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from './components/layout/Layout';
import { Dashboard } from './pages/Dashboard';
import { ActiveScansPage } from './pages/active-scans';
import { PassiveIntelPage } from './pages/passive-intel';
import { FindingsPage } from './pages/findings/FindingsPage';
import { OwaspPage } from './pages/owasp/OwaspPage';
import { CvePage } from './pages/cve/CvePage';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Layout>
        {(currentPath) => {
          switch (currentPath) {
            case 'dashboard':
              return <Dashboard />;
            case 'active-scans':
              return <ActiveScansPage />;
            case 'passive-intel':
              return <PassiveIntelPage />;
            case 'findings':
              return <FindingsPage />;
            case 'owasp':
              return <OwaspPage />;
            case 'cve':
              return <CvePage />;
            default:
              return (
                <div className="p-8 text-center">
                  <div className="text-6xl mb-4">🚧</div>
                  <p className="text-xl text-slate-300">Page under construction...</p>
                </div>
              );
          }
        }}
      </Layout>
    </QueryClientProvider>
  );
}

export default App;
