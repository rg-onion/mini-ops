import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTranslation } from "react-i18next";
import { Languages } from "lucide-react";

export default function Login() {
    const { t, i18n } = useTranslation();
    const [token, setToken] = useState("");

    const handleLogin = () => {
        if (token) {
            localStorage.setItem("auth_token", token);
            window.location.href = "/";
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-100 dark:bg-neutral-900 relative">
            <div className="absolute top-4 right-4">
                <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => i18n.changeLanguage(i18n.language === 'en' ? 'ru' : 'en')}
                    className="gap-2"
                >
                    <Languages className="h-4 w-4" />
                    {i18n.language === 'en' ? 'Русский' : 'English'}
                </Button>
            </div>
            <Card className="w-[350px]">
                <CardHeader>
                    <CardTitle>{t('login.title')}</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="flex flex-col space-y-4">
                        <Input
                            type="password"
                            placeholder={t('login.password_placeholder')}
                            value={token}
                            onChange={(e: React.ChangeEvent<HTMLInputElement>) => setToken(e.target.value)}
                        />
                        <Button onClick={handleLogin}>{t('login.button')}</Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
