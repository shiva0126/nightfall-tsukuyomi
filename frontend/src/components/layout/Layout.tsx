import { useState } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

interface LayoutProps {
  children: (currentPath: string) => React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const [currentPath, setCurrentPath] = useState('dashboard');

  return (
    <div className="flex h-screen bg-gradient-to-br from-slate-900 via-purple-900/20 to-slate-900">
      <Sidebar currentPath={currentPath} onNavigate={setCurrentPath} />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto">
          {children(currentPath)}
        </main>
      </div>
    </div>
  );
}
