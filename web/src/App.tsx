import { Routes, Route } from 'react-router-dom';
import { WorkspaceDashboard } from './components/Dashboard/WorkspaceDashboard';
import { PlanAnalyzer } from './components/PlanViewer/PlanAnalyzer';
import { Header } from './components/Shared/Header';

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <Routes>
          <Route path="/" element={<WorkspaceDashboard />} />
          <Route path="/analyze" element={<PlanAnalyzer />} />
          <Route path="/plans/:planId" element={<PlanAnalyzer />} />
        </Routes>
      </main>
    </div>
  );
}

export default App;
