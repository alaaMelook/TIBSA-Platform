@echo off
cd /d "D:\Desktop\Almost There 🤍⌛\Graduation Project\part 2\TIBSA\frontend"
mkdir "src\app\suspended-account" 2>nul
echo "use client"; > src\app\suspended-account\page.tsx.tmp
echo. >> src\app\suspended-account\page.tsx.tmp
echo import { useEffect } from "react"; >> src\app\suspended-account\page.tsx.tmp
echo import { useAuth } from "@/hooks/useAuth"; >> src\app\suspended-account\page.tsx.tmp
echo import Link from "next/link"; >> src\app\suspended-account\page.tsx.tmp
echo import { motion } from "framer-motion"; >> src\app\suspended-account\page.tsx.tmp
echo import { useRouter } from "next/navigation"; >> src\app\suspended-account\page.tsx.tmp
echo. >> src\app\suspended-account\page.tsx.tmp
echo export default function SuspendedAccountPage^(^) { >> src\app\suspended-account\page.tsx.tmp
echo     const { user, logout } = useAuth^(^); >> src\app\suspended-account\page.tsx.tmp
echo     const router = useRouter^(^); >> src\app\suspended-account\page.tsx.tmp
echo. >> src\app\suspended-account\page.tsx.tmp
echo     useEffect^(^(^) =^> { >> src\app\suspended-account\page.tsx.tmp
echo         if ^(user?.is_active^) { >> src\app\suspended-account\page.tsx.tmp
echo             router.push^("/dashboard"^); >> src\app\suspended-account\page.tsx.tmp
echo         } >> src\app\suspended-account\page.tsx.tmp
echo     }, ^[user?.is_active, router^]^); >> src\app\suspended-account\page.tsx.tmp
echo. >> src\app\suspended-account\page.tsx.tmp
echo     const handleLogout = async ^(^) =^> { >> src\app\suspended-account\page.tsx.tmp
echo         await logout^(^); >> src\app\suspended-account\page.tsx.tmp
echo     }; >> src\app\suspended-account\page.tsx.tmp
echo. >> src\app\suspended-account\page.tsx.tmp
echo     return ^( >> src\app\suspended-account\page.tsx.tmp
echo         ^<div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4"^> >> src\app\suspended-account\page.tsx.tmp
echo             ^<motion.div >> src\app\suspended-account\page.tsx.tmp
echo                 initial={{^{ opacity: 0, scale: 0.95 ^}^}} >> src\app\suspended-account\page.tsx.tmp
echo                 animate={{^{ opacity: 1, scale: 1 ^}^}} >> src\app\suspended-account\page.tsx.tmp
echo                 transition={{^{ duration: 0.4 ^}^}} >> src\app\suspended-account\page.tsx.tmp
echo                 className="w-full max-w-md" >> src\app\suspended-account\page.tsx.tmp
echo             ^> >> src\app\suspended-account\page.tsx.tmp
echo                 ^<div className="bg-slate-800/50 border border-red-500/20 backdrop-blur-xl rounded-2xl p-8 shadow-2xl shadow-red-500/10"^> >> src\app\suspended-account\page.tsx.tmp
echo                     ^<div className="flex justify-center mb-6"^> >> src\app\suspended-account\page.tsx.tmp
echo                         ^<div className="w-16 h-16 rounded-full bg-red-500/20 border border-red-500/30 flex items-center justify-center"^> >> src\app\suspended-account\page.tsx.tmp
echo                             Account Suspended >> src\app\suspended-account\page.tsx.tmp
echo                         ^</div^> >> src\app\suspended-account\page.tsx.tmp
echo                     ^</div^> >> src\app\suspended-account\page.tsx.tmp
echo                     ^<h1 className="text-2xl font-bold text-white text-center mb-2"^>Account Suspended^</h1^> >> src\app\suspended-account\page.tsx.tmp
echo                     ^<button onClick={handleLogout}^>Sign Out^</button^> >> src\app\suspended-account\page.tsx.tmp
echo                 ^</div^> >> src\app\suspended-account\page.tsx.tmp
echo             ^</motion.div^> >> src\app\suspended-account\page.tsx.tmp
echo         ^</div^> >> src\app\suspended-account\page.tsx.tmp
echo     ^); >> src\app\suspended-account\page.tsx.tmp
echo } >> src\app\suspended-account\page.tsx.tmp
echo Folder created successfully
