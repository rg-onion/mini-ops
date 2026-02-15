import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import ContainerList from "./components/ContainerList";
import Login from "./components/Login";
import Layout from "./components/Layout";
import HistoryLog from "./components/HistoryLog";
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
          <Route path="/history" element={<Layout><HistoryLog /></Layout>} />
          <Route path="/security" element={<Layout><SecurityPage /></Layout>} />
          <Route path="/ssh" element={<Layout><SshManagement /></Layout>} />
          <Route path="/login" element={<Login />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
