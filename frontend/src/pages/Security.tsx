import { FileIntegrityCard } from "@/components/FileIntegrityCard";
import { SecurityCard } from "@/components/SecurityCard";
import { SecurityEventsCard } from "@/components/SecurityEventsCard";
import { ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";

export default function SecurityPage() {
    const { t } = useTranslation();

    return (
        <div className="flex-1 space-y-4">
            <div className="flex items-center justify-between space-y-2">
                <h2 className="text-3xl font-bold tracking-tight">{t('security.title')}</h2>
                <div className="flex items-center space-x-2">
                    <ShieldAlert className="h-6 w-6 text-muted-foreground" />
                </div>
            </div>

            <div className="grid gap-4">
                <SecurityEventsCard />
                <FileIntegrityCard />
                <SecurityCard />
            </div>
        </div>
    );
}
