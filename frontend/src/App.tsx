import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { lazy, Suspense, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Toaster } from "sonner";
import { BrowserRouter, Navigate, Routes, Route } from "react-router-dom";
import Login from "./components/Login";
import Layout from "./components/Layout";
import "./App.css";

const Dashboard = lazy(() => import("./components/Dashboard"));
const ContainerList = lazy(() => import("./components/ContainerList"));
const SecurityPage = lazy(() => import("./pages/Security"));
const SshManagement = lazy(() => import("./pages/SshManagement"));

const queryClient = new QueryClient();

function RouteLoading() {
  const { t } = useTranslation();

  return (
    <div
      className="flex min-h-[50vh] items-center justify-center gap-2 text-sm text-muted-foreground"
      role="status"
      aria-live="polite"
    >
      <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" />
      <span>{t("common.loading")}</span>
    </div>
  );
}

function LayoutRoute({ children }: { children: ReactNode }) {
  return (
    <Layout>
      <Suspense fallback={<RouteLoading />}>{children}</Suspense>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Toaster richColors position="top-right" />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<LayoutRoute><Dashboard /></LayoutRoute>} />
          <Route path="/containers" element={<LayoutRoute><ContainerList /></LayoutRoute>} />
          <Route path="/security" element={<LayoutRoute><SecurityPage /></LayoutRoute>} />
          <Route path="/ssh" element={<LayoutRoute><SshManagement /></LayoutRoute>} />
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
