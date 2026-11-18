import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { AuthGate } from "./components/AuthGate.js";
import { ApiSecurityPage } from "./pages/ApiSecurityPage.js";
import { OverviewPage } from "./pages/OverviewPage.js";
import { AssetsPage } from "./pages/AssetsPage.js";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
      refetchOnWindowFocus: true,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AuthGate><OverviewPage /></AuthGate>} />
          <Route path="/app" element={<AuthGate><OverviewPage /></AuthGate>} />
          <Route path="/app/api-security" element={<AuthGate><ApiSecurityPage /></AuthGate>} />
          <Route path="/app/assets" element={<AuthGate><AssetsPage /></AuthGate>} />
          <Route path="*" element={<Navigate to="/app" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
