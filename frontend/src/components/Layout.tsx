import { Link, useLocation } from "react-router-dom";
import { LayoutDashboard, Box, Settings, LogOut, Terminal, History as HistoryIcon, Languages, ShieldAlert } from "lucide-react";
import type { LucideIcon } from "lucide-react";
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

interface NavItem {
    path: string;
    icon: LucideIcon;
    label: string;
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
        i18n.changeLanguage(i18n.language === 'en' ? 'ru' : 'en');
    };

    const navItems: NavItem[] = [
        { path: "/",           icon: LayoutDashboard, label: t('common.dashboard') },
        { path: "/containers", icon: Box,              label: t('common.containers') },
        { path: "/history",    icon: HistoryIcon,      label: t('common.history') },
        { path: "/security",   icon: ShieldAlert,      label: t('security.short_title') },
    ];

    return (
        <div className="flex h-dvh overflow-hidden bg-neutral-50/50 dark:bg-neutral-900 w-full">

            {/* ── Sidebar (desktop only) ───────────────────────────────── */}
            <aside className="hidden md:flex flex-col w-64 shrink-0 border-r bg-background shadow-sm overflow-y-auto z-40">
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
                    {navItems.map(({ path, icon: Icon, label }) => (
                        <Link
                            key={path}
                            to={path}
                            className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all ${isActive(path) ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground"}`}
                        >
                            <Icon className="h-4 w-4" />
                            {label}
                        </Link>
                    ))}

                    <div className="pt-4 mt-4 border-t">
                        <div className="px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                            {t('common.system')}
                        </div>
                        <DiskManager />
                        <button
                            onClick={handleUpdate}
                            className="w-full flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-muted hover:text-foreground text-left transition-all mt-1"
                        >
                            <Settings className="h-4 w-4" />
                            {t('common.update_agent')}
                        </button>
                    </div>
                </nav>

                <div className="p-4 border-t">
                    <Button
                        variant="ghost"
                        className="w-full justify-start text-destructive hover:text-destructive hover:bg-destructive/10"
                        onClick={handleLogout}
                    >
                        <LogOut className="mr-2 h-4 w-4" />
                        {t('common.logout')}
                    </Button>
                    <div className="mt-4 px-3 text-[10px] text-muted-foreground font-mono flex justify-between">
                        <span>{t('common.version')}</span>
                        <span>{version}</span>
                    </div>
                </div>
            </aside>

            {/* ── Content column ───────────────────────────────────────── */}
            <div className="flex flex-col flex-1 min-w-0 overflow-hidden">

                {/* Mobile header */}
                <header className="md:hidden shrink-0 h-14 border-b bg-background flex items-center px-4 justify-between">
                    <div className="flex items-center gap-2">
                        <Terminal className="h-5 w-5 text-primary" />
                        <span className="font-bold tracking-tight">Mini-Ops</span>
                    </div>
                    <div className="flex items-center gap-1">
                        <Button
                            variant="ghost"
                            size="icon"
                            onClick={toggleLanguage}
                            className="h-9 w-9 text-muted-foreground hover:text-foreground"
                        >
                            <Languages className="h-4 w-4" />
                        </Button>
                        <Button
                            variant="ghost"
                            size="icon"
                            onClick={handleLogout}
                            className="h-9 w-9 text-destructive hover:text-destructive hover:bg-destructive/10"
                        >
                            <LogOut className="h-4 w-4" />
                        </Button>
                    </div>
                </header>

                {/* Scrollable main content */}
                <main className="flex-1 overflow-y-auto pb-16 md:pb-0">
                    <div className="container py-6 px-4 md:py-8 md:px-8 max-w-7xl mx-auto">
                        {children}
                    </div>
                </main>

                {/* Mobile bottom navigation — fixed so it's always visible */}
                <nav className="md:hidden fixed bottom-0 left-0 right-0 z-50 border-t bg-background">
                    <div className="flex h-16 gap-1 px-1 items-center">
                        {navItems.map(({ path, icon: Icon, label }) => {
                            const active = isActive(path);
                            return (
                                <Link
                                    key={path}
                                    to={path}
                                    className={`flex flex-1 min-w-0 flex-col items-center justify-center gap-0.5 h-12 rounded-xl transition-all border ${
                                        active
                                            ? "bg-primary text-primary-foreground border-primary shadow-sm"
                                            : "bg-muted text-muted-foreground border-border/70 border-2 hover:text-foreground"
                                    }`}
                                >
                                    <Icon className="h-4 w-4 shrink-0" />
                                    <span className="text-[10px] font-medium leading-none w-full text-center truncate px-1">{label}</span>
                                </Link>
                            );
                        })}
                    </div>
                </nav>

            </div>

            <UpdateDialog open={showUpdateDialog} onOpenChange={setShowUpdateDialog} />
            <Toaster position="top-right" />
        </div>
    );
}
