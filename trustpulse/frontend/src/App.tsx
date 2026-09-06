import { NavLink, Route, Routes } from 'react-router-dom';

import { Dashboard } from './pages/Dashboard';
import { SessionDetail } from './pages/SessionDetail';
import { TrustDevApp } from './pages/TrustDevApp';
import { TrustModelPage } from './pages/TrustModelPage';

const NAV = [
  { to: '/soc', label: 'SOC', end: false },
  { to: '/trustdev', label: 'TrustDev', end: false },
  { to: '/trust-model', label: 'Trust model', end: false },
];

export default function App() {
  return (
    <div className="min-h-full">
      <nav className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center gap-6 px-5 py-3">
          <div className="flex items-center gap-2">
            <span className="inline-flex h-7 w-7 items-center justify-center rounded-md bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/40">
              <span className="h-2 w-2 animate-pulse-ring rounded-full bg-cyan-400" />
            </span>
            <div className="leading-tight">
              <div className="text-sm font-semibold tracking-[0.18em] text-slate-100">
                TRUSTPULSE
              </div>
              <div className="text-[10px] text-slate-500">continuous digital trust</div>
            </div>
          </div>
          <div className="flex items-center gap-1">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `rounded-lg px-3 py-1.5 text-sm transition ${
                    isActive
                      ? 'bg-slate-800 text-slate-100'
                      : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </div>
          <div className="ml-auto hidden text-[11px] text-slate-600 md:block">
            Authenticate once. Trust continuously. Prove why.
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-7xl px-5 py-6">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/soc" element={<Dashboard />} />
          <Route path="/soc/sessions/:sessionId" element={<SessionDetail />} />
          <Route path="/trustdev" element={<TrustDevApp />} />
          <Route path="/trust-model" element={<TrustModelPage />} />
          <Route
            path="*"
            element={
              <div className="py-20 text-center">
                <p className="text-4xl font-semibold text-slate-700">404</p>
                <p className="mt-2 text-sm text-slate-500">That route does not exist.</p>
              </div>
            }
          />
        </Routes>
      </main>

      <footer className="mx-auto max-w-7xl px-5 pb-8 pt-2 text-[11px] leading-relaxed text-slate-600">
        TRUSTPULSE is a prototype. TCI is an engineering trust index, not a probability; behavioral
        signals raise evidence, they never authorize on their own, and every authorization decision
        is made by a server-side Policy Enforcement Point.
      </footer>
    </div>
  );
}
