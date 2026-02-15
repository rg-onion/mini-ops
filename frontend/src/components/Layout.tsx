import { Link, useLocation } from "react-router-dom";
import { LayoutDashboard, Box, Settings, LogOut, Terminal, History as HistoryIcon, Languages, ShieldAlert } from "lucide-react";
import { Button } from "./ui/button";
import { useState, useEffect } from "react";
import { UpdateDialog } from "./UpdateDialog";
import { DiskManager } from "./DiskManager";
import { Toaster } from "sonner";
import { apiFetch } from "@/api";
import { useTranslation } from "react-i18next";

interface LayoutProps {
    children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
    const { t, i18n } = useTranslation();
    const location = useLocation();
    const [showUpdateDialog, setShowUpdateDialog] = useState(false);
    const [version, setVersion] = useState<string>("...");

    useEffect(() => {
        apiFetch("/version").then(res => res.text()).then(setVersion).catch(() => setVersion("error"));
    }, []);

    const isActive = (path: string) => location.pathname === path;

    const handleUpdate = () => {
        if (confirm(t('common.confirm_update'))) {
            setShowUpdateDialog(true);
        }
    };

    const handleLogout = () => {
        localStorage.removeItem("auth_token");
        window.location.href = "/login";
    };

    const toggleLanguage = () => {
        const newLang = i18n.language === 'en' ? 'ru' : 'en';
        i18n.changeLanguage(newLang);
    };

    return (
        <div className="flex min-h-screen bg-neutral-50/50 dark:bg-neutral-900 w-full">
            {/* Sidebar - Sticky */}
            <aside className="sticky top-0 h-screen w-64 shrink-0 border-r bg-background shadow-sm overflow-y-auto z-40">
                <div className="flex h-full flex-col">
                    <div className="flex h-16 items-center px-6 border-b shrink-0 justify-between">
                        <div className="flex items-center">
                            <Terminal className="mr-2 h-6 w-6 text-primary" />
                            <span className="font-bold text-lg tracking-tight">Mini-Ops</span>
                        </div>
                        <Button
                            variant="ghost"
                            size="icon"
                            onClick={toggleLanguage}
                            className="h-8 w-8 text-muted-foreground hover:text-foreground"
                            title={i18n.language === 'en' ? 'RU' : 'EN'}
                        >
                            <Languages className="h-4 w-4" />
                        </Button>
                    </div>

                    <nav className="flex-1 space-y-1 px-4 py-4">
                        <Link to="/" className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all ${isActive("/") ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground"}`}>
                            <LayoutDashboard className="h-4 w-4" />
                            {t('common.dashboard')}
                        </Link>
                        <Link to="/containers" className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all ${isActive("/containers") ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground"}`}>
                            <Box className="h-4 w-4" />
                            {t('common.containers')}
                        </Link>
                        <Link to="/history" className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all ${isActive("/history") ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground"}`}>
                            <HistoryIcon className="h-4 w-4" />
                            {t('common.history')}
                        </Link>
                        <Link to="/security" className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all ${isActive("/security") ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground"}`}>
                            <ShieldAlert className="h-4 w-4" />
                            {t('security.title')}
                        </Link>

                        <div className="pt-4 mt-4 border-t">
                            <div className="px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                                {t('common.system')}
                            </div>
                            <DiskManager />
                            <button onClick={handleUpdate} className="w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-muted hover:text-foreground text-left transition-all mt-1">
                                <Settings className="h-4 w-4" />
                                {t('common.update_agent')}
                            </button>
                        </div>
                    </nav>

                    <div className="p-4 border-t mt-auto">
                        <Button variant="ghost" className="w-full justify-start text-destructive hover:text-destructive hover:bg-destructive/10" onClick={handleLogout}>
                            <LogOut className="mr-2 h-4 w-4" />
                            {t('common.logout')}
                        </Button>
                        <div className="mt-4 px-3 text-[10px] text-muted-foreground font-mono flex justify-between">
                            <span>{t('common.version')}</span>
                            <span>{version}</span>
                        </div>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 w-full overflow-x-hidden">
                <div className="container py-8 px-4 md:px-8 max-w-7xl mx-auto">
                    {children}
                </div>
            </main>

            <UpdateDialog open={showUpdateDialog} onOpenChange={setShowUpdateDialog} />
            <Toaster position="top-right" />
        </div>
    );
}
