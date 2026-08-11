import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import { BrowserRouter, Navigate, Routes, Route } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import ContainerList from "./components/ContainerList";
import Login from "./components/Login";
import Layout from "./components/Layout";
import SecurityPage from "./pages/Security";
import SshManagement from "./pages/SshManagement";
import "./App.css";

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Toaster richColors position="top-right" />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout><Dashboard /></Layout>} />
          <Route path="/containers" element={<Layout><ContainerList /></Layout>} />
          <Route path="/security" element={<Layout><SecurityPage /></Layout>} />
          <Route path="/ssh" element={<Layout><SshManagement /></Layout>} />
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
