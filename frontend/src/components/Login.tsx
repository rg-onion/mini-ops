import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTranslation } from "react-i18next";
import { Languages } from "lucide-react";
import { BASE_URL, clearAuthToken, getAuthHeaders } from "@/api";

export default function Login() {
    const { t, i18n } = useTranslation();
    const [token, setToken] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [isVerifying, setIsVerifying] = useState(false);

    const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();

        const nextToken = token.trim();
        if (!nextToken || isVerifying) return;

        setError(null);
        setIsVerifying(true);

        try {
            const response = await fetch(`${BASE_URL}/version`, {
                headers: getAuthHeaders(nextToken),
            });

            if (!response.ok) {
                clearAuthToken();
                setError(response.status === 401 ? t("login.error") : t("login.verify_error"));
                return;
            }

            localStorage.setItem("auth_token", nextToken);
            window.location.href = "/";
        } catch {
            clearAuthToken();
            setError(t("login.verify_error"));
        } finally {
            setIsVerifying(false);
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-100 dark:bg-neutral-900">
            <Card className="w-[350px]">
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <CardTitle>{t('login.title')}</CardTitle>
                        <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => i18n.changeLanguage(i18n.language === 'en' ? 'ru' : 'en')}
                            className="gap-2 -mr-2"
                        >
                            <Languages className="h-4 w-4" />
                            {i18n.language === 'en' ? 'Русский' : 'English'}
                        </Button>
                    </div>
                </CardHeader>
                <CardContent>
                    <form className="flex flex-col space-y-4" onSubmit={handleLogin}>
                        <Input
                            type="password"
                            placeholder={t('login.password_placeholder')}
                            value={token}
                            onChange={(e) => setToken(e.target.value)}
                            aria-invalid={!!error}
                        />
                        {error && (
                            <p className="text-sm text-destructive" role="alert">
                                {error}
                            </p>
                        )}
                        <Button type="submit" disabled={!token.trim() || isVerifying}>
                            {isVerifying ? t('login.verifying') : t('login.button')}
                        </Button>
                    </form>
                </CardContent>
            </Card>
        </div>
    );
}
